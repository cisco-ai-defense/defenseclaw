#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Compile and verify DefenseClaw's canonical telemetry-registry inputs.

Normal compiler execution is deliberately offline. Upstream semantic-convention
sources are represented by normalized, digest-pinned snapshots created only by
``update_telemetry_registry_upstream.py``.

The compiler renders one exact output inventory in memory. Its small publication
layer stores runtime JSON as canonical gzip and Go sources as ordinary files.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import string
import sys
import tempfile
import unicodedata
import urllib.parse
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, is_dataclass, replace
from dataclasses import fields as dataclass_fields
from pathlib import Path, PurePosixPath
from types import MappingProxyType, ModuleType
from typing import Any, Final, TypeAlias

import yaml
from jsonschema import Draft202012Validator

_GENERATOR_PACKAGE_MODE = (
    __package__ == "scripts" and __spec__ is not None and __spec__.name == "scripts.generate_telemetry_registry"
)


def _canonical_sibling_name(module_name: str) -> str:
    return f"scripts.{module_name}" if _GENERATOR_PACKAGE_MODE else module_name


def _validated_local_module(
    module: Any,
    *,
    canonical_name: str,
    path: Path,
    purpose: str,
) -> ModuleType:
    if not isinstance(module, ModuleType):
        raise RuntimeError(f"preloaded {purpose} is unsafe")
    try:
        module_path = Path(module.__file__).resolve(strict=True)
        module_spec = module.__spec__
        if (
            module.__name__ != canonical_name
            or module_spec is None
            or module_spec.name != canonical_name
            or module_spec.loader is None
            or module_spec.origin is None
        ):
            raise RuntimeError("preloaded module has no canonical import identity")
        origin_path = Path(module_spec.origin).resolve(strict=True)
        regular = stat.S_ISREG(module_path.stat().st_mode) and stat.S_ISREG(origin_path.stat().st_mode)
    except (AttributeError, OSError, RuntimeError, TypeError) as exc:
        raise RuntimeError(f"preloaded {purpose} is unsafe") from exc
    if not regular:
        raise RuntimeError(f"preloaded {purpose} is unsafe")
    if module_path != path or origin_path != path:
        raise RuntimeError(f"preloaded {purpose} has foreign provenance")
    return module


def _loaded_opposite_sibling(
    module_name: str,
    path: Path,
    purpose: str,
) -> ModuleType | None:
    """Reuse an already-loaded sibling from the other supported import form.

    Test runners and embedders may import this script as ``scripts.*`` or by
    file path.  Loading the same dependency twice creates incompatible
    dataclass identities; rejecting the second form made ordinary whole-suite
    execution order-dependent.  The first validated local module now wins for
    the process, regardless of which supported name loaded it.
    """

    opposite_name = module_name if _GENERATOR_PACKAGE_MODE else f"scripts.{module_name}"
    opposite = sys.modules.get(opposite_name)
    if opposite is None:
        return None
    return _validated_local_module(
        opposite,
        canonical_name=opposite_name,
        path=path,
        purpose=purpose,
    )


def _load_local_module(module_name: str, purpose: str) -> ModuleType:
    canonical_name = _canonical_sibling_name(module_name)
    try:
        path = Path(__file__).resolve().with_name(module_name + ".py").resolve(strict=True)
        if not stat.S_ISREG(path.stat().st_mode):
            raise OSError("module is not a regular file")
    except (OSError, RuntimeError) as exc:
        raise RuntimeError(f"cannot load {purpose}") from exc
    existing = sys.modules.get(canonical_name)
    if existing is not None:
        return _validated_local_module(
            existing,
            canonical_name=canonical_name,
            path=path,
            purpose=purpose,
        )
    opposite = _loaded_opposite_sibling(module_name, path, purpose)
    if opposite is not None:
        return opposite
    spec = importlib.util.spec_from_file_location(canonical_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {purpose}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[canonical_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(canonical_name) is module:
            del sys.modules[canonical_name]
        raise
    return module


runtime_assets = _load_local_module(
    "telemetry_runtime_assets",
    "telemetry runtime-asset codec",
)


def _load_sibling_module(module_name: str):  # type: ignore[no-untyped-def]
    """Load one renderer dependency under its canonical process-wide identity."""
    return _load_local_module(module_name, f"telemetry renderer dependency {module_name}")


def _load_candidate_renderers():  # type: ignore[no-untyped-def]
    """Return one identity-coherent portable/Go renderer module set."""

    # The Go renderer constructs coordinator dataclasses and the coordinator
    # validates them with isinstance, so these names must never be path-loaded
    # under competing module identities.
    _load_sibling_module("telemetry_canonical_record")
    coordinator = _load_sibling_module("telemetry_go_output_coordinator")
    _load_sibling_module("telemetry_go_inbound_plan")
    _load_sibling_module("telemetry_go_api_plan")
    _load_sibling_module("telemetry_go_producer_plan")
    _load_sibling_module("telemetry_go_fixture_plan")
    portable = _load_sibling_module("render_telemetry_registry_candidates")
    go_renderer = _load_sibling_module("render_telemetry_go")
    return portable, go_renderer, coordinator


NORMALIZED_SNAPSHOT_FORMAT: Final = "defenseclaw-selected-semconv-v1"
MAX_AUTHORED_JSON_NESTING: Final = 256
EXPECTED_IMPORTS: Final = ("genai.yaml", "security.yaml", "operations.yaml")
EXPECTED_DEPENDENCIES: Final = ("otel_core", "otel_genai", "openinference")
EXPECTED_STRUCTURAL_INPUTS: Final = (
    (
        "model/gen-ai/gen-ai-input-messages.json",
        "schemas/telemetry/v8/upstream/otel-genai-b028dceecdad117461a785c3af35315e7184e813/"
        "model/gen-ai/gen-ai-input-messages.json",
        "034fcd8c87f1e013f3a5a5018503210e2bee4d2499c361823b96e906d40a50ad",
    ),
    (
        "model/gen-ai/gen-ai-output-messages.json",
        "schemas/telemetry/v8/upstream/otel-genai-b028dceecdad117461a785c3af35315e7184e813/"
        "model/gen-ai/gen-ai-output-messages.json",
        "a825a6c0cc1b7b22fdbfb9488d8dc3a318be3897ef6d3dbae01a10297bb6e569",
    ),
    (
        "model/gen-ai/gen-ai-tool-call-arguments.json",
        "schemas/telemetry/v8/upstream/otel-genai-b028dceecdad117461a785c3af35315e7184e813/"
        "model/gen-ai/gen-ai-tool-call-arguments.json",
        "73607a8e8d9e84393475ef460108c59dbb9e1d2ddc0d0177fce6f735a62367ea",
    ),
    (
        "model/gen-ai/gen-ai-tool-call-result.json",
        "schemas/telemetry/v8/upstream/otel-genai-b028dceecdad117461a785c3af35315e7184e813/"
        "model/gen-ai/gen-ai-tool-call-result.json",
        "44eb4a93b05eea7da14489f1d253814c6429772d1fe869f8f6fc1749d7593412",
    ),
)
EXPECTED_STRUCTURED_TYPE_IDS: Final = (
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
EXPECTED_STRUCTURED_BINDINGS: Final = (
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
EXPECTED_GO_SYMBOL_POLICY: Final = {
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
GO_SYMBOL_KIND_ORDER: Final = (
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
GO_SYMBOL_DECLARATION_FORMS: Final = (
    "exported_const",
    "exported_type",
    "exported_function",
    "family_builder_method",
)
_GO_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
_GO_SOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/#-]{0,511}$")
_GO_SOURCE_ID_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_JSON_NUMBER_TOKEN = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$")
_GO_RESERVED_IDENTIFIERS: Final = frozenset(
    {
        "break",
        "default",
        "func",
        "interface",
        "select",
        "case",
        "defer",
        "go",
        "map",
        "struct",
        "chan",
        "else",
        "goto",
        "package",
        "switch",
        "const",
        "fallthrough",
        "if",
        "range",
        "type",
        "continue",
        "for",
        "import",
        "return",
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
EXPECTED_AUTHORED_STRUCTURED_TYPES_SHA256: Final = "8ed3cab115fd647fde11b1aa78dd16386b56a6eec3b0c47ab76e3def1bc73e94"
EXPECTED_MESSAGE_PART_VARIANTS: Final = (
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
EXPECTED_STRUCTURED_OBJECT_FIELDS: Final = {
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
EXPECTED_STRUCTURED_ARRAYS: Final = {
    "gen_ai.input_messages": ("gen_ai.chat_message", 0, 256),
    "gen_ai.output_messages": ("gen_ai.output_message", 0, 256),
    "gen_ai.message_parts": ("gen_ai.message_part", 0, 256),
}
# The pinned OTel GenAI schema requires finish_reason, while DefenseClaw also
# accepts provider responses that legitimately omit it.  Keep the imported
# source contract exact without making the local, lossless representation
# artificially require a value the provider did not report.
STRUCTURED_SOURCE_REQUIRED_OVERRIDES: Final = {
    ("gen_ai.output_message", "finish_reason"): True,
}
STRUCTURED_SOURCE_DEFINITIONS: Final = {
    "model/gen-ai/gen-ai-input-messages.json": {
        "ChatMessage": "gen_ai.chat_message",
        "TextPart": "gen_ai.text_part",
        "ToolCallRequestPart": "gen_ai.tool_call_request_part",
        "ToolCallResponsePart": "gen_ai.tool_call_response_part",
        "ServerToolCallPart": "gen_ai.server_tool_call_part",
        "ServerToolCallResponsePart": "gen_ai.server_tool_call_response_part",
        "BlobPart": "gen_ai.blob_part",
        "FilePart": "gen_ai.file_part",
        "UriPart": "gen_ai.uri_part",
        "ReasoningPart": "gen_ai.reasoning_part",
        "CompactionPart": "gen_ai.compaction_part",
        "GenericPart": "gen_ai.generic_part",
        "GenericServerToolCall": "gen_ai.generic_server_tool_payload",
        "GenericServerToolCallResponse": "gen_ai.generic_server_tool_payload",
    },
    "model/gen-ai/gen-ai-output-messages.json": {
        "OutputMessage": "gen_ai.output_message",
        "TextPart": "gen_ai.text_part",
        "ToolCallRequestPart": "gen_ai.tool_call_request_part",
        "ToolCallResponsePart": "gen_ai.tool_call_response_part",
        "ServerToolCallPart": "gen_ai.server_tool_call_part",
        "ServerToolCallResponsePart": "gen_ai.server_tool_call_response_part",
        "BlobPart": "gen_ai.blob_part",
        "FilePart": "gen_ai.file_part",
        "UriPart": "gen_ai.uri_part",
        "ReasoningPart": "gen_ai.reasoning_part",
        "CompactionPart": "gen_ai.compaction_part",
        "GenericPart": "gen_ai.generic_part",
        "GenericServerToolCall": "gen_ai.generic_server_tool_payload",
        "GenericServerToolCallResponse": "gen_ai.generic_server_tool_payload",
    },
}
STRUCTURED_NULLABLE_OPTIONALS: Final = {
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
EXPECTED_STRUCTURAL_SOURCE_ENUMS: Final = {
    "Modality": ("image", "video", "audio", "document"),
    "Role": ("system", "user", "assistant", "tool"),
    "FinishReason": ("stop", "length", "content_filter", "tool_call", "compaction", "error"),
}
AUDITED_STRUCTURED_SCALARS: Final = {
    ("gen_ai.chat_message", "role"): ("metadata", "internal", "bounded-v1", 256),
    ("gen_ai.chat_message", "name"): ("identifier", "sensitive", "bounded-v1", 512),
    ("gen_ai.output_message", "role"): ("metadata", "internal", "bounded-v1", 256),
    ("gen_ai.output_message", "name"): ("identifier", "sensitive", "bounded-v1", 512),
    ("gen_ai.output_message", "finish_reason"): ("metadata", "internal", "bounded-v1", 256),
    ("gen_ai.tool_call_request_part", "id"): ("identifier", "sensitive", "bounded-v1", 512),
    ("gen_ai.tool_call_request_part", "name"): ("identifier", "internal", "bounded-v1", 512),
    ("gen_ai.tool_call_response_part", "id"): ("identifier", "sensitive", "bounded-v1", 512),
    ("gen_ai.server_tool_call_part", "id"): ("identifier", "sensitive", "bounded-v1", 512),
    ("gen_ai.server_tool_call_part", "name"): ("identifier", "internal", "bounded-v1", 512),
    ("gen_ai.server_tool_call_response_part", "id"): ("identifier", "sensitive", "bounded-v1", 512),
    ("gen_ai.blob_part", "mime_type"): ("metadata", "internal", "bounded-v1", 256),
    ("gen_ai.blob_part", "modality"): ("metadata", "internal", "bounded-v1", 256),
    ("gen_ai.file_part", "mime_type"): ("metadata", "internal", "bounded-v1", 256),
    ("gen_ai.file_part", "modality"): ("metadata", "internal", "bounded-v1", 256),
    ("gen_ai.file_part", "file_id"): ("identifier", "sensitive", "bounded-v1", 512),
    ("gen_ai.uri_part", "mime_type"): ("metadata", "internal", "bounded-v1", 256),
    ("gen_ai.uri_part", "modality"): ("metadata", "internal", "bounded-v1", 256),
    ("gen_ai.uri_part", "uri"): ("path", "sensitive", "path-v1", 8192),
    ("gen_ai.compaction_part", "id"): ("identifier", "sensitive", "bounded-v1", 512),
    ("gen_ai.generic_server_tool_payload", "type"): ("identifier", "internal", "bounded-v1", 256),
}
AUDITED_STRUCTURED_CONTENT_FIELDS: Final = frozenset(
    {
        ("gen_ai.text_part", "content"),
        ("gen_ai.blob_part", "content"),
        ("gen_ai.reasoning_part", "content"),
        ("gen_ai.compaction_part", "content"),
    }
)
EXPECTED_DOMAINS: Final = ("genai", "security", "operations")
EXPECTED_REPOSITORIES: Final = {
    "otel_core": "https://github.com/open-telemetry/semantic-conventions",
    "otel_genai": "https://github.com/open-telemetry/semantic-conventions-genai",
    "openinference": "https://github.com/Arize-ai/openinference",
}
UPSTREAM_PUBLIC_OWNERS: Final = {
    "otel_core": "otel",
    "otel_genai": "otel_genai",
    "openinference": "openinference_compatibility",
}
EXPECTED_OPENINFERENCE_SOURCES: Final = (
    "python/openinference-semantic-conventions/src/openinference/semconv/resource/__init__.py",
    "python/openinference-semantic-conventions/src/openinference/semconv/trace/__init__.py",
    "python/openinference-semantic-conventions/src/openinference/semconv/version.py",
    "spec/semantic_conventions.md",
)
REQUIRED_OPENINFERENCE_ATTRIBUTES: Final = frozenset(
    {
        "openinference.span.kind",
        "input.value",
        "input.mime_type",
        "output.value",
        "output.mime_type",
        "metadata",
        "openinference.project.name",
    }
)
EXPECTED_SEMANTIC_PROFILE: Final = {
    "id": "defenseclaw-genai-rich-v1",
    "trace_schema_version": "defenseclaw-trace-v1",
    "gen_ai_semconv_profile": "otel-genai-b028dceecdad117461a785c3af35315e7184e813",
    "openinference_profile": "openinference-semantic-conventions-v0.1.30",
    "galileo_compatibility_profile": "galileo-rich-v2",
}
EXPECTED_BUCKET_ORDER: Final = (
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
EXPECTED_BUCKETS: Final = frozenset(EXPECTED_BUCKET_ORDER)
EXPECTED_COMPATIBILITY_LOG_IDENTITIES: Final = frozenset(
    {
        "compact_end",
        "compact_start",
        "event",
        "hook_decision",
        "session_end",
        "session_start",
        "subagent_start",
        "subagent_stop",
        "tool_end",
        "tool_start",
        "turn_end",
        "turn_start",
    }
)
EXPECTED_PRODUCER_KINDS: Final = frozenset({"gateway_event", "audit_action"})
EXPECTED_LINK_RELATIONS: Final = frozenset({"caused_by", "correlates_with", "derived_from", "resumes"})
EXPECTED_COMPATIBILITY_PROFILES: Final = frozenset({"galileo-rich-v2", "local-observability-v1", "openinference-v1"})
EXPECTED_SPAN_KINDS: Final = frozenset({"CLIENT", "CONSUMER", "INTERNAL", "PRODUCER", "SERVER"})
V7_EXPORTER_SELECTION_SCHEMA: Final = Path("schemas/telemetry/v8/compatibility/v7-exporter-selection.schema.json")
V7_EXPORTER_SELECTION_SCHEMA_MAX_BYTES: Final = 128 * 1024
GO_CANDIDATE_AUTHORITY: Final = "candidate-not-public-authority"
GO_CANDIDATE_OUTPUT_PATHS: Final = (
    "internal/observability/zz_generated_telemetry_ids.go",
    "internal/observability/zz_generated_telemetry_catalog.go",
    "internal/observability/zz_generated_telemetry_producers.go",
    "internal/observability/zz_generated_telemetry_builders_genai.go",
    "internal/observability/zz_generated_telemetry_builders_security.go",
    "internal/observability/zz_generated_telemetry_builders_operations.go",
    "internal/observability/zz_generated_telemetry_builder_fixtures_test.go",
)
PORTABLE_STATIC_OUTPUT_PATHS: Final = (
    "schemas/telemetry/generated/telemetry.schema.json",
    "schemas/telemetry/generated/catalog.json",
    "schemas/telemetry/generated/catalog.md",
    "schemas/telemetry/generated/compatibility/galileo-rich-v2.json",
    "schemas/telemetry/generated/compatibility/local-observability-v1.json",
    "schemas/telemetry/generated/compatibility/openinference-v1.json",
    "schemas/telemetry/generated/compatibility/v7-exporter-selection.json",
    "schemas/telemetry/generated/compatibility/inbound-otlp.json",
    "schemas/telemetry/generated/examples/manifest.json",
    "schemas/telemetry/generated/otlp-fixtures/manifest.json",
)
# Only runtime/release inputs remain checked in under generated/. The catalog
# report, inbound compatibility expansion, and example/OTLP corpora are useful
# compiler products, but they are reproducible and needlessly dominate diffs.
REPOSITORY_GENERATED_OUTPUT_PATHS: Final = frozenset(
    runtime_assets.LOGICAL_TO_ENCODED
)
REPOSITORY_OUTPUT_MODE: Final = 0o644
REPOSITORY_PHYSICAL_OUTPUT_PATHS: Final = frozenset(
    {
        *runtime_assets.LOGICAL_TO_ENCODED.values(),
        *GO_CANDIDATE_OUTPUT_PATHS,
    }
)
RETIRED_REPOSITORY_OUTPUT_PATHS: Final = frozenset(
    {
        "schemas/telemetry/generated/output-manifest.json",
        *runtime_assets.LOGICAL_TO_ENCODED,
    }
)


def _is_repository_output(path: str) -> bool:
    return not path.startswith("schemas/telemetry/generated/") or path in REPOSITORY_GENERATED_OUTPUT_PATHS


EXPECTED_STRUCTURAL_CONTRACT_ID: Final = "defenseclaw.canonical-record"
EXPECTED_OTLP_REPRESENTATION_ID: Final = "defenseclaw-otlp-v1"
STRUCTURAL_RUNTIME_BINDING_KEYS: Final = (
    "record",
    "input",
    "value",
    "schema_derived_constructor",
    "schema_derived_log_constructor",
)
STRUCTURAL_LIMIT_KEYS: Final = (
    "record_id_utf8_bytes",
    "correlation_id_utf8_bytes",
    "span_name_utf8_bytes",
    "binary_version_utf8_bytes",
    "provenance_hex_ascii_bytes",
    "stable_token_ascii_bytes",
    "payload_depth",
    "payload_members",
    "payload_encoded_bytes",
    "record_encoded_bytes",
)
PROVENANCE_IMPORT_RULE_KEYS: Final = (
    "nonempty_string_fields",
    "derivation_required_modes",
    "derivation_forbidden_modes",
    "source_aggregate_count_required_derivations",
    "source_aggregate_count_forbidden_derivations",
    "source_aggregate_count_forbidden_modes",
    "exact_validation_owner",
    "json_schema_runtime_only",
)
EXPECTED_PROVENANCE_IMPORT_RULES: Final = {
    "nonempty_string_fields": (
        "binding_id",
        "authenticated_source",
        "upstream_instance_id",
        "upstream_record_id",
        "upstream_service_name",
        "upstream_redaction_profile",
        "last_hop_instance_id",
        "last_hop_destination",
    ),
    "derivation_required_modes": ("derive", "import_and_derive"),
    "derivation_forbidden_modes": ("import",),
    "source_aggregate_count_required_derivations": ("arithmetic_mean",),
    "source_aggregate_count_forbidden_derivations": (
        "field_value",
        "elapsed_time",
        "cumulative_delta",
    ),
    "source_aggregate_count_forbidden_modes": ("import",),
    "exact_validation_owner": "internal/observability.ImportProvenance.Validate",
    "json_schema_runtime_only": ("valid_utf8", "utf8_byte_length"),
}
_STRUCTURAL_FIELD_TYPE: Final = frozenset(
    {
        "boolean",
        "int64",
        "uint32",
        "uint64",
        "double",
        "string",
        "timestamp",
        "object",
        "array",
        "canonical_json",
        "field_class_map",
        "metric_number",
    }
)
STRUCTURAL_SEMANTIC_FORMATS: Final = frozenset({"otel-trace-id-v1", "otel-span-id-v1", "w3c-tracestate-v1"})
TRACE_DERIVATION_BINDINGS: Final = (
    (
        "trace-bucket-equality-v1",
        "target_attribute",
        "defenseclaw.bucket",
        "envelope.bucket",
        "typed-json-exact",
        "when-registered",
    ),
    (
        "trace-family-equality-v1",
        "target_attribute",
        "defenseclaw.span.family",
        "family.id",
        "typed-json-exact",
        "when-registered",
    ),
    (
        "trace-family-schema-version-equality-v1",
        "target_attribute",
        "defenseclaw.span.family_schema_version",
        "family.family_schema_version",
        "typed-json-exact",
        "when-registered",
    ),
    (
        "trace-source-equality-v1",
        "target_attribute",
        "defenseclaw.source",
        "envelope.source",
        "typed-json-exact",
        "when-registered",
    ),
    (
        "trace-config-generation-equality-v1",
        "target_attribute",
        "defenseclaw.config.generation",
        "provenance.config_generation",
        "typed-json-exact",
        "when-registered",
    ),
    (
        "trace-outcome-equality-v1",
        "target_attribute",
        "defenseclaw.outcome",
        "envelope.outcome",
        "typed-json-exact",
        "when-registered-and-source-present",
    ),
    (
        "trace-resource-service-version-equality-v1",
        "target_attribute",
        "service.version",
        "provenance.binary_version",
        "typed-json-exact",
        "when-registered",
    ),
    (
        "trace-scope-version-equality-v1",
        "target_field",
        "trace_scope.version",
        "provenance.binary_version",
        "typed-json-exact",
        "when-registered",
    ),
    (
        "trace-scope-schema-version-equality-v1",
        "target_attribute",
        "defenseclaw.trace.schema_version",
        "semantic_profile.trace_schema_version",
        "typed-json-exact",
        "when-registered",
    ),
    (
        "trace-scope-semantic-profile-equality-v1",
        "target_attribute",
        "defenseclaw.semantic_profile",
        "semantic_profile.id",
        "typed-json-exact",
        "when-registered",
    ),
    (
        "trace-link-relation-equality-v1",
        "target_attribute",
        "defenseclaw.link.relation",
        "link.relation",
        "typed-json-exact",
        "when-registered",
    ),
)
TRACE_OUTCOME_PRESENCE_CONDITION: Final = "operation-terminal-v1"
TRACE_SCOPE_SCHEMA_URL: Final = "https://defenseclaw.io/schemas/telemetry/v8"
MATERIALIZED_VIEW_FORMAT: Final = "defenseclaw-materialized-registry-view-v1"
MATERIALIZED_VIEW_DIGEST_DOMAIN: Final = b"DefenseClaw MaterializedRegistryView v1\x00"
PSEUDO_SEMANTIC_REF_PLACEMENTS: Final = {
    "payload.rfc6901_field_classes": ("envelope", "field_classes"),
    "registry.event_or_instrument": ("envelope", "event_name"),
    "registry.family_attributes": ("trace_body", "attributes"),
    "registry.family_payload": ("envelope", "body"),
    "registry.metric_labels": ("metric_instrument_data", "attributes"),
    "registry.metric_value": ("metric_instrument_data", "value"),
    "registry.span_event": ("trace_event", "name"),
    "registry.span_event_attributes": ("trace_event", "attributes"),
}
PSEUDO_SEMANTIC_REFS: Final = frozenset(PSEUDO_SEMANTIC_REF_PLACEMENTS)
OTLP_ANY_VALUE_MAPPING: Final = (
    ("boolean", "boolValue"),
    ("int64", "intValue"),
    ("uint32", "intValue"),
    ("double", "doubleValue"),
    ("string", "stringValue"),
    ("array", "arrayValue"),
    ("object", "kvlistValue"),
)
OTLP_SPAN_KIND_MAPPING: Final = (
    ("INTERNAL", 1),
    ("SERVER", 2),
    ("CLIENT", 3),
    ("PRODUCER", 4),
    ("CONSUMER", 5),
)
OTLP_STATUS_CODE_MAPPING: Final = (("UNSET", 0), ("OK", 1), ("ERROR", 2))
OTLP_OBJECT_CONTEXTS: Final = {
    "envelope": "ResourceSpans.scopeSpans[].spans[]",
    "correlation": "ResourceSpans.scopeSpans[].spans[]",
    "trace_body": "ResourceSpans.scopeSpans[].spans[]",
    "trace_resource": "ResourceSpans.resource",
    "trace_scope": "ResourceSpans.scopeSpans[].scope",
    "trace_status": "ResourceSpans.scopeSpans[].spans[].status",
    "trace_event": "ResourceSpans.scopeSpans[].spans[].events[]",
    "trace_link": "ResourceSpans.scopeSpans[].spans[].links[]",
}
OTLP_FIELD_CONTEXT_OVERRIDES: Final = {
    "trace_resource.schema_url": "ResourceSpans",
    "trace_scope.schema_url": "ResourceSpans.scopeSpans[]",
}
OTLP_FIELD_MAPPINGS: Final = {
    "envelope": {"span_name": ("name", "direct")},
    "correlation": {
        "trace_id": ("traceId", "hex"),
        "span_id": ("spanId", "hex"),
    },
    "trace_body": {
        "kind": ("kind", "enum_number"),
        "start_time_unix_nano": ("startTimeUnixNano", "uint64_string"),
        "end_time_unix_nano": ("endTimeUnixNano", "uint64_string"),
        "parent_span_id": ("parentSpanId", "hex"),
        "trace_state": ("traceState", "direct"),
        "flags": ("flags", "direct"),
        "status": ("status", "message"),
        "attributes": ("attributes", "key_value_array"),
        "dropped_attributes_count": ("droppedAttributesCount", "direct"),
        "events": ("events", "message"),
        "dropped_events_count": ("droppedEventsCount", "direct"),
        "links": ("links", "message"),
        "dropped_links_count": ("droppedLinksCount", "direct"),
    },
    "trace_resource": {
        "schema_url": ("schemaUrl", "direct"),
        "attributes": ("attributes", "key_value_array"),
        "dropped_attributes_count": ("droppedAttributesCount", "direct"),
    },
    "trace_scope": {
        "name": ("name", "direct"),
        "version": ("version", "direct"),
        "schema_url": ("schemaUrl", "direct"),
        "attributes": ("attributes", "key_value_array"),
        "dropped_attributes_count": ("droppedAttributesCount", "direct"),
    },
    "trace_status": {"code": ("code", "enum_number"), "description": ("message", "direct")},
    "trace_event": {
        "name": ("name", "direct"),
        "time_unix_nano": ("timeUnixNano", "uint64_string"),
        "attributes": ("attributes", "key_value_array"),
        "dropped_attributes_count": ("droppedAttributesCount", "direct"),
    },
    "trace_link": {
        "trace_id": ("traceId", "hex"),
        "span_id": ("spanId", "hex"),
        "trace_state": ("traceState", "direct"),
        "attributes": ("attributes", "key_value_array"),
        "dropped_attributes_count": ("droppedAttributesCount", "direct"),
    },
    "metric_instrument_data": {},
    "provenance": {},
    "provenance_import": {},
}

NORMALIZER_KIND_CONTRACTS: Final = {
    "identity-v1": ("identity", frozenset()),
    "bounded-v1": ("bounded", frozenset({"max_utf8_bytes", "max_item_utf8_bytes", "max_items"})),
    "enum-v1": ("enum", frozenset({"max_utf8_bytes"})),
    "identifier-v1": ("identifier", frozenset({"max_utf8_bytes", "pattern"})),
    "numeric-range-v1": ("numeric_range", frozenset()),
    "structured-content-v1": (
        "structured_content",
        frozenset({"max_utf8_bytes", "max_item_utf8_bytes", "max_items", "max_depth", "max_properties"}),
    ),
    "redacted-content-v1": (
        "redacted_content",
        frozenset({"max_utf8_bytes", "max_item_utf8_bytes", "max_items", "max_depth", "max_properties"}),
    ),
    "path-v1": ("path", frozenset({"max_utf8_bytes"})),
    "url-v1": ("url", frozenset({"max_utf8_bytes"})),
    "digest-v1": ("digest", frozenset({"max_utf8_bytes", "pattern"})),
}
EXPECTED_METRIC_CARDINALITY_LIMIT: Final = 2048
EXPECTED_METRIC_PROFILE_LIMITS: Final = {
    "dimensions_cache_size": 10000,
    "resource_metrics_cache_size": 1000,
    "series_expiration": "24h",
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{0,255}$")
_EXAMPLE_ID = re.compile(r"^[a-z][a-z0-9-]{0,127}$")
_RESERVED_DOS_DEVICE_IDS: Final = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{number}" for number in range(1, 10)}
    | {f"lpt{number}" for number in range(1, 10)}
)


def _w3c_tracestate_key_accepts(value: str) -> bool:
    def key_part_accepts(part: str, *, first_may_be_digit: bool, max_tail: int) -> bool:
        if not part or len(part) - 1 > max_tail:
            return False
        first = part[0]
        if not ("a" <= first <= "z" or first_may_be_digit and "0" <= first <= "9"):
            return False
        return all("a" <= char <= "z" or "0" <= char <= "9" or char in "_-*/" for char in part[1:])

    tenant, separator, system = value.partition("@")
    if not separator:
        return key_part_accepts(tenant, first_may_be_digit=False, max_tail=255)
    return key_part_accepts(tenant, first_may_be_digit=True, max_tail=240) and key_part_accepts(
        system,
        first_may_be_digit=False,
        max_tail=13,
    )


def _w3c_tracestate_accepts(value: Any) -> bool:
    """Accept the canonical W3C Trace Context list-member representation."""

    if not isinstance(value, str) or len(value.encode("utf-8")) > 512:
        return False
    if value == "":
        return True
    members = value.split(",")
    if len(members) > 32 or any(not member for member in members):
        return False
    keys: set[str] = set()
    for member in members:
        key, separator, member_value = member.partition("=")
        if not separator or "=" in member_value or not _w3c_tracestate_key_accepts(key) or key in keys:
            return False
        keys.add(key)
        if not 1 <= len(member_value) <= 256:
            return False
        for char in member_value[:-1]:
            codepoint = ord(char)
            if codepoint < 0x20 or codepoint > 0x7E or char in ",=":
                return False
        last = ord(member_value[-1])
        if last < 0x21 or last > 0x7E or member_value[-1] in ",=":
            return False
    return True


_FIELD_TYPE = frozenset(
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
_STABILITY = frozenset({"development", "stable", "deprecated"})
_OWNER = frozenset({"otel", "otel_genai", "openinference_compatibility", "defenseclaw"})
_FIELD_CLASS = frozenset({"metadata", "identifier", "content", "reason", "evidence", "error", "path", "credential"})
_SENSITIVITY = frozenset({"safe", "internal", "sensitive", "critical"})
_CARDINALITY = frozenset({"low", "bounded", "high"})
_METRIC_INSTRUMENT_TYPES = frozenset({"counter", "gauge", "histogram", "updowncounter"})
_METRIC_VALUE_TYPES = frozenset({"int64", "double"})
_METRIC_TEMPORALITIES = frozenset({"delta", "cumulative", "unspecified"})
_CONSTRAINT_KEYS = frozenset(
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
_GROUP_TYPE = frozenset({"attribute_group", "body_group", "resource", "span_event", "log", "span", "metric"})
_SIGNAL_BY_GROUP_TYPE = {"log": "logs", "span": "traces", "metric": "metrics"}
_MANDATORY_RULE_CATALOG_V1: Final = (
    ("always", "constant", True),
    ("control_plane_mutation", "builder_fact", "control_plane_mutation"),
    ("approval_resolution", "builder_fact", "approval_resolution"),
    ("alert_mutation", "builder_fact", "alert_mutation"),
    ("protected_boundary_auth_failure", "builder_fact", "protected_boundary_auth_failure"),
    ("enforced_outcome", "builder_fact", "enforced_outcome"),
    ("enforcement_state_change", "builder_fact", "enforcement_state_change"),
    ("schema_validation_failure", "builder_fact", "schema_validation_failure"),
    ("sqlite_failure", "builder_fact", "sqlite_failure"),
    ("exporter_initialization_failure", "builder_fact", "exporter_initialization_failure"),
    ("durable_health_transition", "builder_fact", "durable_health_transition"),
    ("destination_test_activity", "builder_fact", "destination_test_activity"),
    ("managed_aid_fail_open", "builder_fact", "managed_aid_fail_open"),
)
_COMPANION_RULES = frozenset(
    {
        "enforcement_when_enforced",
        "asset_lifecycle_on_state_change",
        "finding_per_observation",
    }
)
_SEVERITY_POLICIES = frozenset(
    {
        "canonical_or_info",
        "finding_required",
        "evaluation",
        "failure_or_source",
        "malformed_or_source",
    }
)


class RegistryError(ValueError):
    """Safe compiler error containing source paths and schema keys only."""


FrozenJSON: TypeAlias = str | bytes | int | float | bool | None | tuple["FrozenJSON", ...] | Mapping[str, "FrozenJSON"]


def _freeze_json(value: Any) -> FrozenJSON:
    if value is None or type(value) in {str, bytes, int, float, bool}:
        return value
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    raise RegistryError("validated JSON value has an unsupported runtime type")


def _freeze_mapping(value: dict[str, Any]) -> Mapping[str, FrozenJSON]:
    frozen = _freeze_json(value)
    if not isinstance(frozen, Mapping):
        raise RegistryError("validated mapping did not remain a mapping")
    return frozen


def _typed_json_equal(left: Any, right: Any) -> bool:
    """Compare JSON values without Python's bool/int or int/float coercion."""
    if isinstance(left, Mapping) or isinstance(right, Mapping):
        if not isinstance(left, Mapping) or not isinstance(right, Mapping):
            return False
        return left.keys() == right.keys() and all(_typed_json_equal(left[key], right[key]) for key in left)
    if isinstance(left, (list, tuple)) or isinstance(right, (list, tuple)):
        if not isinstance(left, (list, tuple)) or not isinstance(right, (list, tuple)):
            return False
        return len(left) == len(right) and all(
            _typed_json_equal(left_item, right_item) for left_item, right_item in zip(left, right, strict=True)
        )
    return type(left) is type(right) and left == right


def _typed_json_contains(values: Iterable[Any], candidate: Any) -> bool:
    return any(_typed_json_equal(value, candidate) for value in values)


class _StrictLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise RegistryError("YAML mapping keys must be strings")
        if key == "<<":
            raise RegistryError("YAML merge keys are not allowed")
        if key in result:
            raise RegistryError(f"duplicate YAML key {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _read_utf8(path: Path) -> tuple[bytes, str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RegistryError(f"cannot read {path}: {exc.strerror or exc.__class__.__name__}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RegistryError(f"{path}: invalid UTF-8") from exc
    if text.startswith("\ufeff"):
        raise RegistryError(f"{path}: UTF-8 BOM is not allowed")
    return raw, text


def _parse_yaml_strict_bytes(path: Path, raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RegistryError(f"{path}: invalid UTF-8") from exc
    if text.startswith("\ufeff"):
        raise RegistryError(f"{path}: UTF-8 BOM is not allowed")
    try:
        for token in yaml.scan(text):
            if isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken)):
                raise RegistryError(f"{path}: YAML anchors and aliases are not allowed")
            if isinstance(token, yaml.tokens.TagToken):
                raise RegistryError(f"{path}: explicit YAML tags are not allowed")
        value = yaml.load(text, Loader=_StrictLoader)
    except RegistryError:
        raise
    except yaml.YAMLError as exc:
        raise RegistryError(f"{path}: invalid YAML") from exc
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: document root must be a mapping")
    return value


def _load_yaml_strict_with_bytes(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw, _ = _read_utf8(path)
    return raw, _parse_yaml_strict_bytes(path, raw)


def load_yaml_strict(path: Path) -> dict[str, Any]:
    return _load_yaml_strict_with_bytes(path)[1]


def _parse_json_strict_bytes(path: Path, raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RegistryError(f"{path}: invalid UTF-8") from exc
    if text.startswith("\ufeff"):
        raise RegistryError(f"{path}: UTF-8 BOM is not allowed")

    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_AUTHORED_JSON_NESTING:
                raise RegistryError(f"{path}: JSON nesting exceeds the parser limit")
        elif character in "]}":
            depth = max(0, depth - 1)

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise RegistryError(f"{path}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise RegistryError(f"{path}: non-finite JSON number {value!r} is not allowed")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=reject_constant)
    except RegistryError:
        raise
    except json.JSONDecodeError as exc:
        raise RegistryError(f"{path}: invalid JSON") from exc
    except RecursionError as exc:
        raise RegistryError(f"{path}: JSON nesting exceeds the parser limit") from exc
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: document root must be an object")
    return value


def load_json_strict(path: Path) -> dict[str, Any]:
    raw, _ = _read_utf8(path)
    return _parse_json_strict_bytes(path, raw)


def _load_json_strict_with_bytes(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw, _ = _read_utf8(path)
    return raw, _parse_json_strict_bytes(path, raw)


def _exact_keys(value: dict[str, Any], required: set[str], optional: set[str], path: str) -> None:
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing:
        raise RegistryError(f"{path}: missing keys {sorted(missing)}")
    if unknown:
        raise RegistryError(f"{path}: unknown keys {sorted(unknown)}")


def _integer(
    value: Any,
    path: str,
    *,
    minimum: int = 1,
    maximum: int | None = None,
) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        expectation = f">= {minimum}" if maximum is None else f"in [{minimum}, {maximum}]"
        raise RegistryError(f"{path}: expected integer {expectation}")
    return value


def _string(value: Any, path: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
        raise RegistryError(f"{path}: expected a nonempty bounded string")
    if pattern is not None and not pattern.fullmatch(value):
        raise RegistryError(f"{path}: invalid string syntax")
    return value


def _string_list(value: Any, path: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise RegistryError(f"{path}: expected a string sequence")
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        item = _string(item, f"{path}[{index}]")
        if item in seen:
            raise RegistryError(f"{path}: duplicate value")
        result.append(item)
        seen.add(item)
    return tuple(result)


def _safe_relative(root: Path, value: str, path: str, *, prefix: Path) -> tuple[Path, str]:
    if "\\" in value:
        raise RegistryError(f"{path}: paths must use forward slashes")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts or relative == Path("."):
        raise RegistryError(f"{path}: path must remain repository-relative")
    repository_path = (root / relative).resolve()
    allowed = (root / prefix).resolve()
    try:
        repository_path.relative_to(allowed)
    except ValueError as exc:
        raise RegistryError(f"{path}: path leaves {prefix.as_posix()}") from exc
    return repository_path, relative.as_posix()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _public_upstream_owner(dependency_id: str) -> str:
    owner = UPSTREAM_PUBLIC_OWNERS.get(dependency_id)
    if owner is None:
        raise RegistryError(f"upstream dependency {dependency_id}: no public attribute-owner mapping")
    return owner


@dataclass(frozen=True, slots=True)
class InputDigest:
    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class SourceFileIR:
    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class StructuralInputIR:
    upstream_path: str
    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class SnapshotAttribute:
    id: str
    allowed_types: tuple[str, ...]
    shape: str
    stability: str
    stability_source: str
    source_pointer: str
    enum: tuple[str, ...]
    deprecated: bool


@dataclass(frozen=True, slots=True)
class SnapshotIR:
    format_version: int
    format: str
    dependency_id: str
    repository: str
    revision: str
    path: str
    sha256: str
    source_archive_url: str
    source_archive_sha256: str
    source_tree_sha256: str
    full_normalized_inventory_sha256: str
    selection_policy: str
    selection_attribute_ids_sha256: str
    source_files: tuple[SourceFileIR, ...]
    attributes: tuple[SnapshotAttribute, ...]


@dataclass(frozen=True, slots=True)
class DependencyIR:
    id: str
    repository: str
    version: str
    profile_id: str
    revision: str
    snapshot: SnapshotIR
    structural_inputs: tuple[StructuralInputIR, ...]


@dataclass(frozen=True, slots=True)
class NormalizerIR:
    id: str
    kind: str
    default_constraints: Mapping[str, FrozenJSON]
    allowed_overrides: tuple[str, ...]
    __hash__ = None


@dataclass(frozen=True, slots=True)
class NormalizationIR:
    id: str
    overrides: Mapping[str, FrozenJSON]
    effective_constraints: Mapping[str, FrozenJSON]
    notes: str | None
    __hash__ = None


@dataclass(frozen=True, slots=True)
class LegacyBindingIR:
    source: str
    disposition: str
    details_present: bool
    details: FrozenJSON | None
    __hash__ = None


@dataclass(frozen=True, slots=True)
class AttributeIR:
    id: str
    field_type: str
    brief: str
    examples: tuple[FrozenJSON, ...]
    alias_of: str | None
    owner: str
    stability: str
    deprecated_in: str | None
    removed_in: str | None
    projection_only: bool
    field_class: str
    sensitivity: str
    cardinality: str
    normalization: NormalizationIR
    introduced_in: str
    legacy_bindings: tuple[LegacyBindingIR, ...] | None
    __hash__ = None


@dataclass(frozen=True, slots=True)
class AttributeExtensionIR:
    ref: str
    field_class: str
    sensitivity: str
    cardinality: str
    normalization: NormalizationIR
    __hash__ = None


@dataclass(frozen=True, slots=True)
class MetricProjectionIR:
    profile: str
    mappings: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class DerivedSpanmetricsIR:
    pipeline: str
    dimensions_cache_size: int
    resource_metrics_cache_size: int
    series_expiration: str


@dataclass(frozen=True, slots=True)
class MetricCompatibilityProfileIR:
    id: str
    high_cardinality_families: Mapping[str, tuple[str, ...]]
    derived_spanmetrics: DerivedSpanmetricsIR
    __hash__ = None


@dataclass(frozen=True, slots=True)
class MetricInventoryIR:
    instrument_type: str
    unit: str
    labels: frozenset[str]
    empty_labels_reason: str | None


@dataclass(frozen=True, slots=True)
class AttributeUseIR:
    ref: str
    role: str
    requirement_level: str
    conditional: str | None
    constraints: Mapping[str, FrozenJSON]
    __hash__ = None


@dataclass(frozen=True, slots=True)
class AttributeUseOriginIR:
    group_id: str
    role: str
    requirement_level: str
    conditional: str | None
    constraints: Mapping[str, FrozenJSON]
    __hash__ = None


@dataclass(frozen=True, slots=True)
class ResolvedAttributeUseIR:
    ref: str
    role: str
    requirement_level: str
    conditional: str | None
    constraints: Mapping[str, FrozenJSON]
    origins: tuple[AttributeUseOriginIR, ...]
    __hash__ = None


@dataclass(frozen=True, slots=True)
class ConditionEnforcementIR:
    kind: str
    fact: str | None
    attribute: str | None


@dataclass(frozen=True, slots=True)
class ConditionIR:
    id: str
    description: str
    enforcement: ConditionEnforcementIR
    false_requirement: str


@dataclass(frozen=True, slots=True)
class MandatoryRuleEnforcementIR:
    kind: str
    value: bool | None
    fact: str | None


@dataclass(frozen=True, slots=True)
class MandatoryRuleIR:
    id: str
    enforcement: MandatoryRuleEnforcementIR


@dataclass(frozen=True, slots=True)
class MandatoryRuleCatalogIR:
    version: int
    rules: tuple[MandatoryRuleIR, ...]


@dataclass(frozen=True, slots=True)
class StructuredScalarIR:
    field_type: str
    field_class: str
    sensitivity: str
    normalization: NormalizationIR
    encoding_annotation: str | None
    known_values: tuple[str, ...]
    __hash__ = None


@dataclass(frozen=True, slots=True)
class StructuredReferenceIR:
    structured_ref: str


@dataclass(frozen=True, slots=True)
class StructuredFieldIR:
    name: str
    required: bool
    nullable_omission: bool
    scalar: StructuredScalarIR | None
    reference: StructuredReferenceIR | None


@dataclass(frozen=True, slots=True)
class StructuredDynamicNameIR:
    field_type: str
    field_class: str
    sensitivity: str
    normalization: NormalizationIR
    __hash__ = None


@dataclass(frozen=True, slots=True)
class StructuredDynamicMembersIR:
    member_id: str
    name: StructuredDynamicNameIR
    value: StructuredReferenceIR
    max_items: int
    public_encoding: str
    wire_encoding: str
    duplicate_name_policy: str
    fixed_name_collision_policy: str
    post_redaction_name_collision_policy: str
    reserved_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StructuredDiscriminatorIR:
    name: str
    field_type: str
    field_class: str
    sensitivity: str
    normalization: NormalizationIR
    __hash__ = None


@dataclass(frozen=True, slots=True)
class StructuredVariantIR:
    tag: str
    structured_ref: str


@dataclass(frozen=True, slots=True)
class StructuredDynamicVariantIR:
    arm_id: str
    tag_normalization: NormalizationIR
    structured_ref: str
    exclude_registered_tags: bool
    __hash__ = None


@dataclass(frozen=True, slots=True)
class CanonicalJSONLimitsIR:
    max_depth: int
    max_aggregate_members: int
    max_array_items: int
    max_string_utf8_bytes: int
    max_member_name_utf8_bytes: int
    max_item_bytes: int
    max_canonical_bytes: int


@dataclass(frozen=True, slots=True)
class CanonicalJSONContractIR:
    discriminator_visibility: str
    discriminator_wire: bool
    arms: tuple[str, ...]
    leaf_field_class: str
    leaf_sensitivity: str
    array_items_ref: str
    object_member_id: str
    object_name: StructuredDynamicNameIR
    object_value: StructuredReferenceIR
    public_encoding: str
    wire_encoding: str
    duplicate_name_policy: str
    fixed_name_collision_policy: str
    post_redaction_name_collision_policy: str
    limits: CanonicalJSONLimitsIR
    __hash__ = None


@dataclass(frozen=True, slots=True)
class StructuredTypeIR:
    id: str
    kind: str
    introduced_in: str
    additional_properties: bool | None
    fields: tuple[StructuredFieldIR, ...] | None
    dynamic_members: StructuredDynamicMembersIR | None
    items_scalar: StructuredScalarIR | None
    items_reference: StructuredReferenceIR | None
    min_items: int | None
    max_items: int | None
    discriminator: StructuredDiscriminatorIR | None
    variants: tuple[StructuredVariantIR, ...] | None
    dynamic_variant: StructuredDynamicVariantIR | None
    canonical_json: CanonicalJSONContractIR | None
    effective_reserved_names: tuple[str, ...]
    __hash__ = None


@dataclass(frozen=True, slots=True)
class StructuredBindingIR:
    attribute: str
    structured_type: str
    public_encoding: str
    canonical_wire_encoding: str


@dataclass(frozen=True, slots=True)
class StructuredPropertyDispositionIR:
    input_path: str
    json_pointer: str
    disposition: str
    structured_type: str
    member_name: str | None
    arm_id: str | None
    target_structured_type: str | None


@dataclass(frozen=True, slots=True)
class ValueCatalogEntryIR:
    value: str
    code: int


@dataclass(frozen=True, slots=True)
class ValueCatalogCompatibilityIR:
    value: str
    code: int
    canonical_emittable: bool


@dataclass(frozen=True, slots=True)
class ValueCatalogIR:
    id: str
    kind: str
    value_attributes: tuple[str, ...]
    paired_value_attribute: str
    code_attribute: str
    entries: tuple[ValueCatalogEntryIR, ...]
    compatibility: ValueCatalogCompatibilityIR


@dataclass(frozen=True, slots=True)
class StructuralFieldIR:
    name: str
    field_type: str
    required: bool
    const_present: bool
    const: FrozenJSON | None
    enum: tuple[FrozenJSON, ...]
    object_ref: str | None
    item_ref: str | None
    semantic_ref: str | None
    semantic_format: str | None
    field_class: str | None
    sensitivity: str | None
    normalization: NormalizationIR | None
    otlp_target: str | None
    otlp_encoding: str | None
    __hash__ = None


@dataclass(frozen=True, slots=True)
class StructuralObjectIR:
    id: str
    additional_properties: bool
    fields: tuple[StructuralFieldIR, ...]


@dataclass(frozen=True, slots=True)
class ProvenanceImportRulesIR:
    nonempty_string_fields: tuple[str, ...]
    derivation_required_modes: tuple[str, ...]
    derivation_forbidden_modes: tuple[str, ...]
    source_aggregate_count_required_derivations: tuple[str, ...]
    source_aggregate_count_forbidden_derivations: tuple[str, ...]
    source_aggregate_count_forbidden_modes: tuple[str, ...]
    exact_validation_owner: str
    json_schema_runtime_only: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SignalArmIR:
    signal: str
    payload_field: str
    required_fields: tuple[str, ...]
    forbidden_fields: tuple[str, ...]
    required_correlation_fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StructuralRelationIR:
    id: str
    kind: str
    left: str
    right: str


@dataclass(frozen=True, slots=True)
class TraceDerivationIR:
    id: str
    target_attribute: str | None
    target_field: str | None
    source: str
    equality: str
    presence: str


@dataclass(frozen=True, slots=True)
class OTLPSignalRepresentationIR:
    signal: str
    mode: str
    request_root: str | None


@dataclass(frozen=True, slots=True)
class CanonicalOTLPRepresentationIR:
    id: str
    json_mapping: str
    attribute_encoding: str
    any_value_encoding: str
    any_value_mapping: tuple[tuple[str, str], ...]
    null_value_policy: str
    object_contexts: Mapping[str, str]
    # Preserved for the next candidate-renderer slice; this manifest-only slice
    # validates placement but deliberately does not render OTLP protobuf JSON.
    field_context_overrides: Mapping[str, str]
    timestamp_encoding: str
    id_encoding: str
    span_kind_mapping: tuple[tuple[str, int], ...]
    status_code_mapping: tuple[tuple[str, int], ...]
    signals: tuple[OTLPSignalRepresentationIR, ...]
    __hash__ = None


@dataclass(frozen=True, slots=True)
class StructuralRuntimeBindingIR:
    record: str
    input: str
    value: str
    schema_derived_constructor: str
    schema_derived_log_constructor: str


@dataclass(frozen=True, slots=True)
class StructuralLimitsIR:
    values: Mapping[str, int]
    __hash__ = None


@dataclass(frozen=True, slots=True)
class StructuralContractIR:
    id: str
    version: int
    additional_properties: bool
    runtime_binding: StructuralRuntimeBindingIR
    limits: StructuralLimitsIR
    envelope: StructuralObjectIR
    correlation: StructuralObjectIR
    provenance: StructuralObjectIR
    provenance_import: StructuralObjectIR
    provenance_import_rules: ProvenanceImportRulesIR
    signal_arms: tuple[SignalArmIR, ...]
    trace_derivations: tuple[TraceDerivationIR, ...]
    trace_body: StructuralObjectIR
    trace_relations: tuple[StructuralRelationIR, ...]
    trace_resource: StructuralObjectIR
    trace_scope: StructuralObjectIR
    trace_status: StructuralObjectIR
    trace_event: StructuralObjectIR
    trace_link: StructuralObjectIR
    metric_instrument_data: StructuralObjectIR
    canonical_to_otlp: CanonicalOTLPRepresentationIR


@dataclass(frozen=True, slots=True)
class ProducerCompatibilityIR:
    introduced_in: str | None
    legacy_event_prefix: str | None
    disposition: str | None
    removal_version: str | None


@dataclass(frozen=True, slots=True)
class SpanNamePartIR:
    kind: str
    literal: str | None
    field: str | None

    def __post_init__(self) -> None:
        if self.kind == "literal":
            valid = isinstance(self.literal, str) and bool(self.literal) and self.field is None
        elif self.kind == "field":
            valid = self.literal is None and isinstance(self.field, str) and _ID.fullmatch(self.field) is not None
        else:
            valid = False
        if not valid:
            raise ValueError("span-name part must contain exactly one nonempty literal or canonical field arm")


@dataclass(frozen=True, slots=True)
class ResourceDynamicMembersIR:
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
    forbidden_key_segments: tuple[str, ...]
    reserved_keys: tuple[str, ...]
    forbidden_value_classes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ResourceCompatibilityAliasIR:
    alias: str
    canonical: str


@dataclass(frozen=True, slots=True)
class GroupIR:
    id: str
    type: str
    brief: str
    stability: str
    extends: tuple[str, ...]
    attribute_uses: tuple[AttributeUseIR, ...]
    attribute_refs: tuple[str, ...]
    resolved_uses: tuple[ResolvedAttributeUseIR, ...]
    event_refs: tuple[str, ...] | None
    event_name: str | None
    bucket: str | None
    span_name_pattern: str | None
    span_name_parts: tuple[SpanNamePartIR, ...] | None
    span_kinds: tuple[str, ...] | None
    span_status_rule: str | None
    instrument_name: str | None
    instrument_type: str | None
    metric_value_type: str | None
    metric_unit: str | None
    metric_description: str | None
    metric_temporality: str | None
    metric_boundaries: tuple[int | float, ...] | None
    empty_labels_reason: str | None
    metric_projections: tuple[MetricProjectionIR, ...]
    family_schema_version: int | None
    outcome_requirement: str | None
    allowed_outcomes: tuple[str, ...] | None
    link_relations: tuple[str, ...] | None
    mandatory_floor: tuple[str, ...] | None
    route_selector: bool | None
    compatibility_profiles: tuple[str, ...] | None
    resource_dynamic_members: ResourceDynamicMembersIR | None
    resource_compatibility_aliases: tuple[ResourceCompatibilityAliasIR, ...] | None
    legacy_bindings: tuple[LegacyBindingIR, ...] | None
    introduced_in: str | None
    deprecated_in: str | None
    removed_in: str | None
    __hash__ = None


@dataclass(frozen=True, slots=True)
class ProducerIdentityIR:
    event_name: str
    bucket: str
    family: str | None
    compatibility_only: bool


@dataclass(frozen=True, slots=True)
class ProducerMappingIR:
    producer: str
    key: str
    source: str
    event_name_policy: str
    severity_policy: str
    mandatory_rules: tuple[str, ...] | None
    companion_rules: tuple[str, ...] | None
    compatibility: ProducerCompatibilityIR | None
    default_identity: ProducerIdentityIR | None
    context_identity_set_id: str | None
    allowed_context_identities: tuple[ProducerIdentityIR, ...]


@dataclass(frozen=True, slots=True)
class ProducerIdentitySetIR:
    id: str
    identities: tuple[ProducerIdentityIR, ...]


@dataclass(frozen=True, slots=True)
class DomainIR:
    domain: str
    path: str
    attributes: tuple[AttributeIR, ...]
    attribute_extensions: tuple[AttributeExtensionIR, ...]
    groups: tuple[GroupIR, ...]
    producer_identity_sets: tuple[ProducerIdentitySetIR, ...]
    producer_mappings: tuple[ProducerMappingIR, ...]
    __hash__ = None


@dataclass(frozen=True, slots=True)
class BuilderOccurrenceIR:
    timestamp: str
    record_id: str


@dataclass(frozen=True, slots=True)
class BuilderFactIR:
    fact: str
    value: bool


@dataclass(frozen=True, slots=True)
class BuilderContextInheritanceIR:
    mode: str
    base_example: str | None


@dataclass(frozen=True, slots=True)
class BuilderContextIR:
    inheritance: BuilderContextInheritanceIR
    occurrence: BuilderOccurrenceIR | None
    condition_facts: tuple[BuilderFactIR, ...]
    mandatory_facts: tuple[BuilderFactIR, ...]


@dataclass(frozen=True, slots=True)
class ExampleIR:
    id: str
    valid: bool
    signal: str
    description: str
    family: str | None
    record: Mapping[str, FrozenJSON]
    expected_error: str | None
    field_classes: Mapping[str, str]
    base_example: str | None
    mutation: ExampleMutationIR | None
    builder_context: BuilderContextIR
    __hash__ = None


@dataclass(frozen=True, slots=True)
class ExampleMutationChangeIR:
    op: str
    path: str
    value_present: bool
    value: FrozenJSON | None
    __hash__ = None


@dataclass(frozen=True, slots=True)
class ExampleMutationIR:
    kind: str
    changes: tuple[ExampleMutationChangeIR, ...]
    __hash__ = None


@dataclass(frozen=True, slots=True)
class SemanticProfileIR:
    id: str
    trace_schema_version: str
    gen_ai_semconv_profile: str
    openinference_profile: str
    galileo_compatibility_profile: str


@dataclass(frozen=True, slots=True)
class UpstreamAttributeOwnershipIR:
    ref: str
    owner: str


@dataclass(frozen=True, slots=True)
class GoSymbolPolicyIR:
    version: int
    package: str
    separators: tuple[str, ...]
    brand_spellings: Mapping[str, str]
    initialisms: tuple[str, ...]
    reserved_word_policy: str
    collision_policy: str
    auto_suffix_policy: str
    __hash__ = None


@dataclass(frozen=True, slots=True)
class GoSymbolOverrideIR:
    kind: str
    source_id: str
    symbol: str
    reason: str


@dataclass(frozen=True, slots=True)
class GoSymbolIR:
    kind: str
    source_id: str
    symbol: str
    declaration_form: str


@dataclass(frozen=True, slots=True)
class GoSymbolTableIR:
    version: int
    package: str
    rows: tuple[GoSymbolIR, ...]
    kind_counts: Mapping[str, int]
    declaration_form_counts: Mapping[str, int]
    table_sha256: str
    __hash__ = None


@dataclass(frozen=True, slots=True)
class MaterializedRegistryView:
    format: str
    facts: Mapping[str, FrozenJSON]
    typed_canonical_json_sha256: str
    __hash__ = None


@dataclass(frozen=True, slots=True)
class InboundOTLPIR:
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


@dataclass(frozen=True, slots=True)
class RegistryIR:
    registry_path: str
    schema_version: int
    registry_version: int
    bucket_catalog_version: int
    imports: tuple[str, ...]
    dependency_lock_path: str
    examples_path: str
    v7_exporter_selection_schema_path: str
    input_digests: tuple[InputDigest, ...]
    dependencies: tuple[DependencyIR, ...]
    semantic_profiles: tuple[SemanticProfileIR, ...]
    go_symbol_policy: GoSymbolPolicyIR
    go_symbol_overrides: tuple[GoSymbolOverrideIR, ...]
    go_symbol_table: GoSymbolTableIR
    normalizers: tuple[NormalizerIR, ...]
    conditions: tuple[ConditionIR, ...]
    mandatory_rule_catalog: MandatoryRuleCatalogIR
    structured_types: tuple[StructuredTypeIR, ...]
    structured_bindings: tuple[StructuredBindingIR, ...]
    structured_property_dispositions: tuple[StructuredPropertyDispositionIR, ...]
    value_catalogs: tuple[ValueCatalogIR, ...]
    structural_contract: StructuralContractIR
    metric_cardinality_limit: int
    metric_compatibility_profile: MetricCompatibilityProfileIR
    v7_exporter_selection: Mapping[str, FrozenJSON]
    v7_exporter_selection_schema: Mapping[str, FrozenJSON]
    inbound_bindings: InboundOTLPIR
    domains: tuple[DomainIR, ...]
    group_resolution_order: tuple[str, ...]
    resolved_group_uses: Mapping[str, tuple[ResolvedAttributeUseIR, ...]]
    examples: tuple[ExampleIR, ...]
    upstream_attribute_ownership: tuple[UpstreamAttributeOwnershipIR, ...]
    legacy_only_upstream_attributes: tuple[str, ...]
    materialized_view: MaterializedRegistryView
    __hash__ = None


def _parse_snapshot(
    root: Path,
    dependency: dict[str, Any],
    dependency_path: str,
) -> SnapshotIR:
    snapshot = dependency["snapshot"]
    if not isinstance(snapshot, dict):
        raise RegistryError(f"{dependency_path}.snapshot: expected mapping")
    _exact_keys(snapshot, {"path", "format", "sha256"}, set(), f"{dependency_path}.snapshot")
    if snapshot["format"] != NORMALIZED_SNAPSHOT_FORMAT:
        raise RegistryError(f"{dependency_path}.snapshot.format: unsupported format")
    expected_digest = _string(snapshot["sha256"], f"{dependency_path}.snapshot.sha256", pattern=_SHA256)
    snapshot_path, snapshot_relative = _safe_relative(
        root,
        _string(snapshot["path"], f"{dependency_path}.snapshot.path"),
        f"{dependency_path}.snapshot.path",
        prefix=Path("schemas/telemetry/v8/upstream"),
    )
    raw, _ = _read_utf8(snapshot_path)
    actual_digest = _sha256(raw)
    if actual_digest != expected_digest:
        raise RegistryError(f"{dependency_path}.snapshot.sha256: snapshot digest mismatch")
    document = _parse_json_strict_bytes(snapshot_path, raw)
    _exact_keys(
        document,
        {
            "format_version",
            "format",
            "dependency_id",
            "repository",
            "revision",
            "source_archive",
            "source_tree_sha256",
            "full_normalized_inventory_sha256",
            "selection",
            "source_files",
            "attributes",
        },
        set(),
        snapshot_relative,
    )
    if _integer(document["format_version"], f"{snapshot_relative}.format_version") != 2:
        raise RegistryError(f"{snapshot_relative}.format_version: unsupported version")
    if document["format"] != NORMALIZED_SNAPSHOT_FORMAT:
        raise RegistryError(f"{snapshot_relative}.format: unsupported format")
    dependency_id = _string(dependency["id"], f"{dependency_path}.id", pattern=_ID)
    repository = _string(dependency["repository"], f"{dependency_path}.repository")
    if EXPECTED_REPOSITORIES.get(dependency_id) != repository:
        raise RegistryError(f"{dependency_path}.repository: not the pinned primary upstream")
    revision = _string(dependency["revision"], f"{dependency_path}.revision", pattern=_REVISION)
    for key, expected in (
        ("dependency_id", dependency_id),
        ("repository", repository),
        ("revision", revision),
    ):
        if document[key] != expected:
            raise RegistryError(f"{snapshot_relative}.{key}: lock/snapshot mismatch")
    archive = document["source_archive"]
    if not isinstance(archive, dict):
        raise RegistryError(f"{snapshot_relative}.source_archive: expected object")
    _exact_keys(archive, {"url", "sha256"}, set(), f"{snapshot_relative}.source_archive")
    archive_url = _string(archive["url"], f"{snapshot_relative}.source_archive.url")
    archive_sha256 = _string(
        archive["sha256"], f"{snapshot_relative}.source_archive.sha256", pattern=_SHA256
    )
    if revision not in archive_url or not archive_url.startswith(repository.rstrip("/") + "/archive/"):
        raise RegistryError(f"{snapshot_relative}.source_archive.url: must name the pinned primary revision")
    source_tree_sha256 = _string(
        document["source_tree_sha256"], f"{snapshot_relative}.source_tree_sha256", pattern=_SHA256
    )
    full_inventory_sha256 = _string(
        document["full_normalized_inventory_sha256"],
        f"{snapshot_relative}.full_normalized_inventory_sha256",
        pattern=_SHA256,
    )
    selection = document["selection"]
    if not isinstance(selection, dict):
        raise RegistryError(f"{snapshot_relative}.selection: expected object")
    _exact_keys(selection, {"policy", "attribute_ids_sha256"}, set(), f"{snapshot_relative}.selection")
    selection_policy = _string(selection["policy"], f"{snapshot_relative}.selection.policy")
    expected_selection_policy = (
        "runtime-profile-vocabulary-v1" if dependency_id == "openinference" else "authored-extension-closure-v1"
    )
    if selection_policy != expected_selection_policy:
        raise RegistryError(f"{snapshot_relative}.selection.policy: unexpected policy")
    selection_attribute_ids_sha256 = _string(
        selection["attribute_ids_sha256"],
        f"{snapshot_relative}.selection.attribute_ids_sha256",
        pattern=_SHA256,
    )
    source_files = document["source_files"]
    if not isinstance(source_files, list) or not source_files:
        raise RegistryError(f"{snapshot_relative}.source_files: expected nonempty sequence")
    source_paths: list[str] = []
    parsed_source_files: list[SourceFileIR] = []
    for index, item in enumerate(source_files):
        item_path = f"{snapshot_relative}.source_files[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected object")
        _exact_keys(item, {"path", "sha256"}, set(), item_path)
        source_path = _string(item["path"], f"{item_path}.path")
        source_digest = _string(item["sha256"], f"{item_path}.sha256", pattern=_SHA256)
        source_paths.append(source_path)
        parsed_source_files.append(SourceFileIR(source_path, source_digest))
    if source_paths != sorted(set(source_paths)):
        raise RegistryError(f"{snapshot_relative}.source_files: paths must be sorted and unique")
    if dependency_id == "openinference" and not set(source_paths).issubset(
        EXPECTED_OPENINFERENCE_SOURCES
    ):
        raise RegistryError(f"{snapshot_relative}.source_files: non-authoritative OpenInference source")
    raw_attributes = document["attributes"]
    if not isinstance(raw_attributes, list) or not raw_attributes:
        raise RegistryError(f"{snapshot_relative}.attributes: expected nonempty sequence")
    attributes: list[SnapshotAttribute] = []
    for index, item in enumerate(raw_attributes):
        item_path = f"{snapshot_relative}.attributes[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected object")
        _exact_keys(
            item,
            {
                "id",
                "allowed_types",
                "shape",
                "stability",
                "stability_source",
                "source_pointer",
                "enum",
                "deprecated",
            },
            set(),
            item_path,
        )
        attribute_id = _string(item["id"], f"{item_path}.id", pattern=_ID)
        allowed_types = _string_list(item["allowed_types"], f"{item_path}.allowed_types")
        shape = _string(item["shape"], f"{item_path}.shape")
        if shape not in {"attribute", "any_value", "indexed_prefix", "object_prefix"}:
            raise RegistryError(f"{item_path}.shape: unsupported normalized field shape")
        direct_types = {
            "string",
            "boolean",
            "int64",
            "double",
            "string[]",
            "boolean[]",
            "int64[]",
            "double[]",
            "bytes",
        }
        if shape == "attribute":
            if not allowed_types or not set(allowed_types).issubset(direct_types):
                raise RegistryError(f"{item_path}.allowed_types: unsupported direct wire type")
            if len(allowed_types) > 1 and allowed_types != ("string", "int64"):
                raise RegistryError(f"{item_path}.allowed_types: unsupported wire union")
        elif allowed_types:
            raise RegistryError(f"{item_path}.allowed_types: non-attribute shapes have no direct wire type")
        stability = _string(item["stability"], f"{item_path}.stability")
        if stability not in _STABILITY:
            raise RegistryError(f"{item_path}.stability: unsupported stability")
        stability_source = _string(item["stability_source"], f"{item_path}.stability_source")
        expected_stability_source = "released_package_policy" if dependency_id == "openinference" else "upstream"
        if stability_source != expected_stability_source:
            raise RegistryError(f"{item_path}.stability_source: unexpected provenance policy")
        pointer = _string(item["source_pointer"], f"{item_path}.source_pointer")
        pointer_source = pointer.split("#", 1)[0]
        if pointer_source not in source_paths or "#" not in pointer:
            raise RegistryError(f"{item_path}.source_pointer: does not resolve to source_files")
        enum = _string_list(item["enum"], f"{item_path}.enum")
        if type(item["deprecated"]) is not bool:
            raise RegistryError(f"{item_path}.deprecated: expected boolean")
        attributes.append(
            SnapshotAttribute(
                id=attribute_id,
                allowed_types=allowed_types,
                shape=shape,
                stability=stability,
                stability_source=stability_source,
                source_pointer=pointer,
                enum=enum,
                deprecated=item["deprecated"],
            )
        )
    ids = [item.id for item in attributes]
    if ids != sorted(set(ids)):
        raise RegistryError(f"{snapshot_relative}.attributes: IDs must be sorted and unique")
    observed_selection_sha256 = _sha256(_canonical_json_bytes(ids))
    if observed_selection_sha256 != selection_attribute_ids_sha256:
        raise RegistryError(f"{snapshot_relative}.selection.attribute_ids_sha256: selected inventory mismatch")
    if dependency_id == "openinference":
        if any(attribute_id.startswith("gen_ai.") for attribute_id in ids):
            raise RegistryError(f"{snapshot_relative}.attributes: foreign gen_ai.* ownership")
        if set(ids) != REQUIRED_OPENINFERENCE_ATTRIBUTES:
            raise RegistryError(f"{snapshot_relative}.attributes: OpenInference runtime vocabulary mismatch")
        for attribute in attributes:
            expected_source = (
                EXPECTED_OPENINFERENCE_SOURCES[0]
                if attribute.id == "openinference.project.name"
                else "spec/semantic_conventions.md"
            )
            if not attribute.source_pointer.startswith(expected_source + "#"):
                raise RegistryError(f"{snapshot_relative}.attributes: OpenInference source pointer policy mismatch")
    return SnapshotIR(
        format_version=document["format_version"],
        format=document["format"],
        dependency_id=dependency_id,
        repository=repository,
        revision=revision,
        path=snapshot_relative,
        sha256=actual_digest,
        source_archive_url=archive_url,
        source_archive_sha256=archive_sha256,
        source_tree_sha256=source_tree_sha256,
        full_normalized_inventory_sha256=full_inventory_sha256,
        selection_policy=selection_policy,
        selection_attribute_ids_sha256=selection_attribute_ids_sha256,
        source_files=tuple(parsed_source_files),
        attributes=tuple(attributes),
    )


def _parse_structural_inputs(
    root: Path,
    value: Any,
    path: str,
) -> tuple[tuple[StructuralInputIR, ...], Mapping[str, dict[str, Any]], tuple[InputDigest, ...]]:
    if not isinstance(value, list):
        raise RegistryError(f"{path}: expected sequence")
    parsed: list[StructuralInputIR] = []
    documents: dict[str, dict[str, Any]] = {}
    digests: list[InputDigest] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(item, {"upstream_path", "path", "sha256"}, set(), item_path)
        upstream_path = _string(item["upstream_path"], f"{item_path}.upstream_path")
        expected_path = _string(item["path"], f"{item_path}.path")
        expected_digest = _string(item["sha256"], f"{item_path}.sha256", pattern=_SHA256)
        source_path, normalized = _safe_relative(
            root,
            expected_path,
            f"{item_path}.path",
            prefix=Path("schemas/telemetry/v8/upstream"),
        )
        raw, _ = _read_utf8(source_path)
        actual_digest = _sha256(raw)
        if actual_digest != expected_digest:
            raise RegistryError(f"{item_path}.sha256: structural input digest mismatch")
        document = _parse_json_strict_bytes(source_path, raw)
        if upstream_path in documents:
            raise RegistryError(f"{path}: duplicate structural upstream path")
        parsed.append(StructuralInputIR(upstream_path, normalized, actual_digest))
        documents[upstream_path] = document
        digests.append(InputDigest(normalized, actual_digest))
    observed = tuple((item.upstream_path, item.path, item.sha256) for item in parsed)
    if observed != EXPECTED_STRUCTURAL_INPUTS:
        raise RegistryError(f"{path}: structural input inventory/order mismatch")
    return tuple(parsed), MappingProxyType(documents), tuple(digests)


def _parse_lock(
    root: Path,
    relative: str,
) -> tuple[
    tuple[DependencyIR, ...],
    InputDigest,
    Mapping[str, dict[str, Any]],
    tuple[InputDigest, ...],
]:
    path, normalized = _safe_relative(
        root,
        relative,
        "registry.dependency_lock",
        prefix=Path("schemas/telemetry/v8"),
    )
    raw, document = _load_yaml_strict_with_bytes(path)
    _exact_keys(document, {"schema_version", "dependencies"}, set(), normalized)
    if _integer(document["schema_version"], f"{normalized}.schema_version") != 1:
        raise RegistryError(f"{normalized}.schema_version: unsupported version")
    raw_dependencies = document["dependencies"]
    if not isinstance(raw_dependencies, list):
        raise RegistryError(f"{normalized}.dependencies: expected sequence")
    dependencies: list[DependencyIR] = []
    structural_documents: Mapping[str, dict[str, Any]] = MappingProxyType({})
    structural_digests: tuple[InputDigest, ...] = ()
    for index, item in enumerate(raw_dependencies):
        item_path = f"{normalized}.dependencies[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(
            item,
            {"id", "repository", "version", "profile_id", "revision", "snapshot"},
            {"structural_inputs"},
            item_path,
        )
        snapshot = _parse_snapshot(root, item, item_path)
        if snapshot.dependency_id == "otel_genai":
            if "structural_inputs" not in item:
                raise RegistryError(f"{item_path}.structural_inputs: required for otel_genai")
            parsed_inputs, structural_documents, structural_digests = _parse_structural_inputs(
                root,
                item["structural_inputs"],
                f"{item_path}.structural_inputs",
            )
        else:
            if "structural_inputs" in item:
                raise RegistryError(f"{item_path}.structural_inputs: only otel_genai may declare structural inputs")
            parsed_inputs = ()
        dependencies.append(
            DependencyIR(
                id=snapshot.dependency_id,
                repository=snapshot.repository,
                version=_string(item["version"], f"{item_path}.version"),
                profile_id=_string(item["profile_id"], f"{item_path}.profile_id", pattern=_ID),
                revision=snapshot.revision,
                snapshot=snapshot,
                structural_inputs=parsed_inputs,
            )
        )
    ids = tuple(item.id for item in dependencies)
    if ids != EXPECTED_DEPENDENCIES:
        raise RegistryError(f"{normalized}.dependencies: expected canonical order {EXPECTED_DEPENDENCIES}")
    return (
        tuple(dependencies),
        InputDigest(normalized, _sha256(raw)),
        structural_documents,
        structural_digests,
    )


def _parse_producer_inventory(
    root: Path,
) -> tuple[
    dict[str, frozenset[str]],
    dict[str, MetricInventoryIR],
    Mapping[str, FrozenJSON],
    InputDigest,
]:
    relative = "docs/design/observability-v8/current-state-inventory.yaml"
    path, normalized = _safe_relative(
        root,
        relative,
        "producer_inventory",
        prefix=Path("docs/design/observability-v8"),
    )
    raw, document = _load_yaml_strict_with_bytes(path)
    if document.get("inventory_version") != 1 or not isinstance(document.get("classes"), dict):
        raise RegistryError(f"{normalized}: unsupported producer inventory")
    classes = document["classes"]
    result: dict[str, frozenset[str]] = {}
    for producer, section_name in (
        ("gateway_event", "gateway_event_types"),
        ("audit_action", "audit_actions"),
    ):
        section = classes.get(section_name)
        if not isinstance(section, dict) or not isinstance(section.get("items"), dict):
            raise RegistryError(f"{normalized}.classes.{section_name}.items: expected mapping")
        values = tuple(
            _string(value, f"{normalized}.classes.{section_name}.items.{constant}", pattern=_ID)
            for constant, value in section["items"].items()
        )
        if len(values) != len(set(values)):
            raise RegistryError(f"{normalized}.classes.{section_name}.items: duplicate producer key")
        if not values:
            raise RegistryError(f"{normalized}.classes.{section_name}.items: inventory is empty")
        result[producer] = frozenset(values)
    metrics_section = classes.get("emitted_metrics")
    if not isinstance(metrics_section, dict) or not isinstance(metrics_section.get("items"), dict):
        raise RegistryError(f"{normalized}.classes.emitted_metrics.items: expected mapping")
    metric_inventory: dict[str, MetricInventoryIR] = {}
    for instrument, item in metrics_section["items"].items():
        item_path = f"{normalized}.classes.emitted_metrics.items.{instrument}"
        _string(instrument, f"{item_path}.name", pattern=_ID)
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(
            item,
            {"type", "unit", "labels", "callsites", "dropped_by_current_global_v8_gate"},
            {"empty_labels_reason"},
            item_path,
        )
        instrument_type = _string(item["type"], f"{item_path}.type")
        if instrument_type not in _METRIC_INSTRUMENT_TYPES:
            raise RegistryError(f"{item_path}.type: unsupported metric instrument type")
        unit = _string(item["unit"], f"{item_path}.unit")
        labels = frozenset(_string_list(item["labels"], f"{item_path}.labels"))
        _string_list(item["callsites"], f"{item_path}.callsites", allow_empty=False)
        dropped = set(
            _string_list(
                item["dropped_by_current_global_v8_gate"],
                f"{item_path}.dropped_by_current_global_v8_gate",
            )
        )
        if not dropped.issubset(labels):
            raise RegistryError(f"{item_path}.dropped_by_current_global_v8_gate: expected a subset of labels")
        empty_reason = None
        if "empty_labels_reason" in item:
            empty_reason = _string(item["empty_labels_reason"], f"{item_path}.empty_labels_reason")
        if bool(labels) == bool(empty_reason):
            requirement = "forbidden" if labels else "required"
            raise RegistryError(f"{item_path}.empty_labels_reason: {requirement}")
        metric_inventory[instrument] = MetricInventoryIR(
            instrument_type,
            unit,
            labels,
            empty_reason,
        )
    if not metric_inventory:
        raise RegistryError(f"{normalized}.classes.emitted_metrics.items: inventory is empty")
    selection = classes.get("v7_exporter_selection")
    if not isinstance(selection, dict):
        raise RegistryError(f"{normalized}.classes.v7_exporter_selection: expected mapping")
    _exact_keys(
        selection,
        {
            "source",
            "migration_disposition",
            "schema_version",
            "source_config_version",
            "projection_profile",
            "collection",
            "exporters",
            "features",
            "span_filter_operations",
            "local_observability",
        },
        set(),
        f"{normalized}.classes.v7_exporter_selection",
    )
    if selection["source"] != "canonical telemetry families plus this v7 current-state inventory":
        raise RegistryError(f"{normalized}.classes.v7_exporter_selection.source: unexpected authority")
    if selection["migration_disposition"] != "preserve_compatibility_floor":
        raise RegistryError(f"{normalized}.classes.v7_exporter_selection.migration_disposition: unexpected value")
    selection_payload = {
        key: value for key, value in selection.items() if key not in {"source", "migration_disposition"}
    }
    return result, metric_inventory, _freeze_mapping(selection_payload), InputDigest(normalized, _sha256(raw))


def _read_v7_exporter_selection_schema(
    root: Path,
) -> tuple[Mapping[str, FrozenJSON], InputDigest]:
    path, normalized = _safe_relative(
        root,
        V7_EXPORTER_SELECTION_SCHEMA.as_posix(),
        "v7_exporter_selection_schema",
        prefix=Path("schemas/telemetry/v8/compatibility"),
    )
    raw, schema = _load_json_strict_with_bytes(path)
    if len(raw) > V7_EXPORTER_SELECTION_SCHEMA_MAX_BYTES:
        raise RegistryError(f"{normalized}: schema exceeds the compiler byte limit")
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:
        raise RegistryError(f"{normalized}: invalid JSON Schema") from exc
    return _freeze_mapping(schema), InputDigest(normalized, _sha256(raw))


def _v7_exporter_selection_document(
    selection: Mapping[str, FrozenJSON],
    *,
    schema_version: int,
    registry_version: int,
    materialized_view_sha256: str,
) -> dict[str, Any]:
    payload = _thaw_json(selection)
    if not isinstance(payload, dict):
        raise RegistryError("v7 exporter selection did not remain a mapping")
    return {
        "x-defenseclaw-generated": {
            "artifact": "compatibility/v7-exporter-selection.json",
            "authority": GO_CANDIDATE_AUTHORITY,
            "generator": "defenseclaw-telemetry-candidate-renderer-v1",
            "materialized_view_sha256": materialized_view_sha256,
            "registry_version": registry_version,
        },
        **payload,
        "registry_schema_version": schema_version,
    }


def _materialize_v7_exporter_selection(
    selection: Mapping[str, FrozenJSON],
    domains: tuple[DomainIR, ...] | list[DomainIR],
    producer_inventory: Mapping[str, frozenset[str]],
    metric_inventory: Mapping[str, MetricInventoryIR],
) -> Mapping[str, FrozenJSON]:
    """Replace closed producer-derived selectors with their canonical identities.

    The current-state inventory owns the v7 policy shape, while the telemetry
    registry's exhaustive producer mappings own the actual action and event-name
    vocabulary.  Keeping only these derivation declarations in the inventory
    prevents a second hand-maintained list from silently losing new producers.
    """

    payload = _thaw_json(selection)
    if not isinstance(payload, dict) or not isinstance(payload.get("exporters"), dict):
        raise RegistryError("v7 exporter selection source did not remain a mapping")
    mappings = [mapping for domain in domains for mapping in domain.producer_mappings]
    metric_groups = [group for domain in domains for group in domain.groups if group.type == "metric"]
    metric_instruments = {group.instrument_name for group in metric_groups}
    if None in metric_instruments or not set(metric_inventory).issubset(metric_instruments):
        raise RegistryError("v7 exporter selection metrics: legacy metric inventory contains an unknown family")
    metric_buckets = list(EXPECTED_BUCKET_ORDER)
    span_event_names = sorted(group.id for domain in domains for group in domain.groups if group.type == "span")
    if not metric_groups or not span_event_names:
        raise RegistryError("v7 exporter selection metrics: canonical family coverage is incomplete")

    collection = payload.get("collection")
    always = collection.get("always") if isinstance(collection, dict) else None
    always_logs = always.get("logs") if isinstance(always, dict) else None
    if always_logs != {"derive_buckets_from": "local_log_producers"}:
        raise RegistryError("v7 exporter selection collection.always.logs: expected local_log_producers derivation")
    always["logs"] = list(EXPECTED_BUCKET_ORDER)
    for condition, signal in (("otel.logs", "logs"), ("otel.traces", "traces")):
        policy = collection.get(condition) if isinstance(collection, dict) else None
        selected = policy.get(signal) if isinstance(policy, dict) else None
        if selected != {"derive_buckets_from": "catalog_v1"}:
            raise RegistryError(
                f"v7 exporter selection collection.{condition}.{signal}: expected catalog_v1 derivation"
            )
        policy[signal] = list(EXPECTED_BUCKET_ORDER)
    otel_metrics = collection.get("otel.metrics") if isinstance(collection, dict) else None
    metric_collection = otel_metrics.get("metrics") if isinstance(otel_metrics, dict) else None
    if metric_collection != {"derive_buckets_from": "emitted_metrics"}:
        raise RegistryError(
            "v7 exporter selection collection.otel.metrics.metrics: expected emitted_metrics derivation"
        )
    otel_metrics["metrics"] = metric_buckets
    mappings_by_producer = {
        producer: tuple(mapping for mapping in mappings if mapping.producer == producer)
        for producer in producer_inventory
    }
    for producer, expected_keys in producer_inventory.items():
        observed_keys = {mapping.key for mapping in mappings_by_producer[producer]}
        if observed_keys != expected_keys:
            raise RegistryError(f"v7 exporter selection {producer}: producer inventory is incomplete")

    gateway_event_names: set[str] = set()
    for mapping in mappings_by_producer["gateway_event"]:
        identities = (
            () if mapping.default_identity is None else (mapping.default_identity,)
        ) + mapping.allowed_context_identities
        if not identities:
            raise RegistryError(f"v7 exporter selection gateway_event/{mapping.key}: no reachable canonical identity")
        gateway_event_names.update(identity.event_name for identity in identities)
    if not gateway_event_names:
        raise RegistryError("v7 exporter selection gateway_event: empty canonical identity set")

    exporters = payload["exporters"]
    for exporter in ("generic_otlp", "local_observability"):
        profile = exporters.get(exporter)
        logs = profile.get("logs") if isinstance(profile, dict) else None
        traces = profile.get("traces") if isinstance(profile, dict) else None
        metrics = profile.get("metrics") if isinstance(profile, dict) else None
        if logs != {"derive_buckets_from": "catalog_v1"}:
            raise RegistryError(f"v7 exporter selection exporters.{exporter}.logs: expected catalog_v1 derivation")
        if traces != {"derive_event_names_from": "span_families"}:
            raise RegistryError(f"v7 exporter selection exporters.{exporter}.traces: expected span_families derivation")
        if metrics != {"derive_buckets_from": "emitted_metrics"}:
            raise RegistryError(
                f"v7 exporter selection exporters.{exporter}.metrics: expected emitted_metrics derivation"
            )
        profile["logs"] = [{"buckets": list(EXPECTED_BUCKET_ORDER)}]
        profile["traces"] = [{"event_names": span_event_names}]
        profile["metrics"] = [{"buckets": metric_buckets}]
    derivations: tuple[tuple[str, str, str], ...] = (
        ("gateway_jsonl", "derive_event_names_from", "gateway_event"),
        ("gateway_console", "derive_event_names_from", "gateway_event"),
    )
    for exporter, declaration, producer in derivations:
        profile = exporters.get(exporter)
        logs = profile.get("logs") if isinstance(profile, dict) else None
        if logs != {declaration: producer}:
            raise RegistryError(
                f"v7 exporter selection exporters.{exporter}.logs: expected the closed {declaration} declaration"
            )
        profile["logs"] = [{"event_names": sorted(gateway_event_names)}]

    audit_profile = exporters.get("audit_sink")
    audit_logs = audit_profile.get("logs") if isinstance(audit_profile, dict) else None
    expected_audit_gateway_keys = ("verdict", "llm_prompt", "llm_response", "tool_invocation")
    if audit_logs != {
        "derive_actions_from": "audit_action",
        "derive_event_names_from_gateway_event_keys": list(expected_audit_gateway_keys),
    }:
        raise RegistryError(
            "v7 exporter selection exporters.audit_sink.logs: expected the closed audit/gateway derivation declaration"
        )
    gateway_mapping_by_key = {mapping.key: mapping for mapping in mappings_by_producer["gateway_event"]}
    forwarded_event_names: set[str] = set()
    for key in expected_audit_gateway_keys:
        mapping = gateway_mapping_by_key.get(key)
        if mapping is None:
            raise RegistryError(f"v7 exporter selection audit_sink: unknown gateway event key {key}")
        identities = (
            () if mapping.default_identity is None else (mapping.default_identity,)
        ) + mapping.allowed_context_identities
        forwarded_event_names.update(identity.event_name for identity in identities)
    audit_profile["logs"] = [
        {"actions": sorted(producer_inventory["audit_action"])},
        {"event_names": sorted(forwarded_event_names)},
    ]

    return _freeze_mapping(payload)


def _validate_v7_exporter_selection(
    selection: Mapping[str, FrozenJSON],
    schema: Mapping[str, FrozenJSON],
    *,
    schema_version: int,
    registry_version: int,
    groups: Mapping[str, GroupIR],
    domains: tuple[DomainIR, ...] | list[DomainIR],
    producer_inventory: Mapping[str, frozenset[str]],
) -> None:
    document = _v7_exporter_selection_document(
        selection,
        schema_version=schema_version,
        registry_version=registry_version,
        materialized_view_sha256="0" * 64,
    )
    validator = Draft202012Validator(_thaw_json(schema))
    errors = sorted(validator.iter_errors(document), key=lambda item: tuple(str(part) for part in item.absolute_path))
    if errors:
        location = "/".join(str(part) for part in errors[0].absolute_path) or "$"
        raise RegistryError(f"v7 exporter selection schema violation at {location}")

    collection = document["collection"]
    for condition in ("otel.logs", "otel.traces", "otel.metrics"):
        selected_signal = condition.split(".", 1)[1]
        if any(collection[condition][signal] for signal in ("logs", "traces", "metrics") if signal != selected_signal):
            raise RegistryError(f"v7 exporter selection {condition}: cross-signal collection is forbidden")

    canonical_buckets = set(EXPECTED_BUCKETS)
    canonical_events = {
        value
        for group in groups.values()
        for value in (group.id, group.event_name, group.instrument_name)
        if value is not None
    }
    producer_events = {
        identity.event_name
        for domain in domains
        for mapping in domain.producer_mappings
        for identity in (
            (() if mapping.default_identity is None else (mapping.default_identity,))
            + mapping.allowed_context_identities
        )
    }
    known_events = canonical_events | producer_events
    canonical_actions = producer_inventory["audit_action"]
    for condition in document["collection"].values():
        for buckets in condition.values():
            if not set(buckets).issubset(canonical_buckets):
                raise RegistryError("v7 exporter selection collection references an unknown bucket")

    selectors: list[Mapping[str, Any]] = []
    for exporter in document["exporters"].values():
        for signal_selectors in exporter.values():
            selectors.extend(signal_selectors)
    selectors.extend(document["features"].get("otel_individual_findings", ()))
    for operation in document["span_filter_operations"].values():
        selectors.extend(operation["selectors"])
    for selector in selectors:
        if not set(selector.get("buckets", ())).issubset(canonical_buckets):
            raise RegistryError("v7 exporter selection references an unknown bucket")
        if not set(selector.get("event_names", ())).issubset(known_events):
            raise RegistryError("v7 exporter selection references an unknown event or family")
        if not set(selector.get("actions", ())).issubset(canonical_actions):
            raise RegistryError("v7 exporter selection references an unknown audit action")

    for exporter, profile, signals in (("galileo", "galileo-rich-v2", ("traces",)),):
        for signal in signals:
            group_type = {"logs": "log", "traces": "span", "metrics": "metric"}[signal]
            selected_groups: set[str] = set()
            for selector in document["exporters"][exporter][signal]:
                selected_buckets = set(selector.get("buckets", ()))
                selected_events = set(selector.get("event_names", ()))
                selected_groups.update(
                    group.id
                    for group in groups.values()
                    if group.type == group_type
                    and (
                        (selected_buckets and group.bucket in selected_buckets)
                        or (selected_events and group.id in selected_events)
                    )
                )
            if not selected_groups:
                raise RegistryError(f"v7 exporter selection {exporter}.{signal}: no canonical families selected")
            ineligible = sorted(
                group_id
                for group_id in selected_groups
                if profile not in (groups[group_id].compatibility_profiles or ())
            )
            if ineligible:
                raise RegistryError(f"v7 exporter selection {exporter}.{signal}: families lack {profile} compatibility")

    route_count = sum(
        len(signal_selectors) for signal_selectors in document["exporters"]["generic_otlp"].values()
    ) + len(document["features"]["otel_individual_findings"])
    if route_count > 256:
        raise RegistryError("v7 exporter selection exceeds the generic OTel route limit")


def _validate_json_compatible(value: Any, path: str, *, depth: int = 0) -> None:
    if depth > 8:
        raise RegistryError(f"{path}: compatibility details exceed maximum depth")
    if value is None or type(value) in {bool, int, float, str}:
        if isinstance(value, float) and not math.isfinite(value):
            raise RegistryError(f"{path}: non-finite numbers are not allowed")
        if isinstance(value, str) and len(value.encode("utf-8")) > 4096:
            raise RegistryError(f"{path}: string exceeds maximum length")
        return
    if isinstance(value, list):
        if len(value) > 256:
            raise RegistryError(f"{path}: sequence exceeds maximum length")
        for index, item in enumerate(value):
            _validate_json_compatible(item, f"{path}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 256:
            raise RegistryError(f"{path}: object exceeds maximum size")
        for key, item in value.items():
            if not isinstance(key, str) or len(key.encode("utf-8")) > 4096:
                raise RegistryError(f"{path}.key: expected a bounded string")
            _validate_json_compatible(item, f"{path}.{key}", depth=depth + 1)
        return
    raise RegistryError(f"{path}: unsupported compatibility-details value")


def _validate_portable_pattern(value: Any, path: str) -> str:
    pattern = _string(value, path)

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
                body = pattern[index + 1 : closing]
                quantifier = re.fullmatch(r"([0-9]+)(?:,([0-9]*))?", body)
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
        raise RegistryError(f"{path}: pattern uses syntax outside the portable RE2 subset")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise RegistryError(f"{path}: invalid pattern") from exc
    return pattern


def _validate_constraint_map(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    unknown = value.keys() - _CONSTRAINT_KEYS
    if unknown:
        raise RegistryError(f"{path}: unknown keys {sorted(unknown)}")
    result: dict[str, Any] = {}
    for key, item in value.items():
        item_path = f"{path}.{key}"
        if item is None:
            raise RegistryError(f"{item_path}: null cannot remove a constraint")
        if key == "enum":
            if not isinstance(item, list) or not item:
                raise RegistryError(f"{item_path}: expected nonempty JSON-scalar sequence")
            normalized: list[str | bool | int | float] = []
            seen: set[tuple[type[Any], Any]] = set()
            for index, entry in enumerate(item):
                if type(entry) not in {str, bool, int, float} or (type(entry) is float and not math.isfinite(entry)):
                    raise RegistryError(f"{item_path}[{index}]: expected finite JSON scalar")
                marker = (type(entry), entry)
                if marker in seen:
                    raise RegistryError(f"{item_path}: duplicate enum value")
                seen.add(marker)
                normalized.append(entry)
            result[key] = normalized
        elif key == "pattern":
            result[key] = _validate_portable_pattern(item, item_path)
        elif key in {
            "min_items",
            "max_items",
            "max_utf8_bytes",
            "max_item_utf8_bytes",
            "max_depth",
            "max_properties",
        }:
            minimum = 0 if key == "min_items" else 1
            result[key] = _integer(item, item_path, minimum=minimum)
        else:
            if type(item) not in {int, float} or (type(item) is float and not math.isfinite(item)):
                raise RegistryError(f"{item_path}: expected finite number")
            result[key] = item
    if "min" in result and "max" in result and result["min"] > result["max"]:
        raise RegistryError(f"{path}: min exceeds max")
    if "min_items" in result and "max_items" in result and result["min_items"] > result["max_items"]:
        raise RegistryError(f"{path}: min_items exceeds max_items")
    return result


def _parse_normalizer_catalog(value: Any, path: str) -> tuple[NormalizerIR, ...]:
    if not isinstance(value, list):
        raise RegistryError(f"{path}: expected sequence")
    parsed: list[NormalizerIR] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(
            item,
            {"id", "kind", "default_constraints", "allowed_overrides"},
            set(),
            item_path,
        )
        normalizer_id = _string(item["id"], f"{item_path}.id", pattern=_ID)
        kind = _string(item["kind"], f"{item_path}.kind", pattern=_ID)
        defaults = _validate_constraint_map(
            item["default_constraints"],
            f"{item_path}.default_constraints",
        )
        overrides = _string_list(item["allowed_overrides"], f"{item_path}.allowed_overrides")
        if not set(overrides).issubset(_CONSTRAINT_KEYS):
            raise RegistryError(f"{item_path}.allowed_overrides: unknown constraint")
        parsed.append(
            NormalizerIR(
                normalizer_id,
                kind,
                _freeze_mapping(defaults),
                overrides,
            )
        )
    by_id = {item.id: item for item in parsed}
    if len(by_id) != len(parsed):
        raise RegistryError(f"{path}: duplicate normalizer ID")
    if set(by_id) != set(NORMALIZER_KIND_CONTRACTS):
        raise RegistryError(f"{path}: normalizer kind inventory mismatch")
    for normalizer_id, (expected_kind, required_defaults) in NORMALIZER_KIND_CONTRACTS.items():
        normalizer = by_id[normalizer_id]
        if normalizer.kind != expected_kind:
            raise RegistryError(f"{path}: {normalizer_id} kind mismatch")
        if not required_defaults.issubset(normalizer.default_constraints):
            raise RegistryError(f"{path}: {normalizer_id} lacks mandatory default bounds")
        if not set(normalizer.default_constraints).issubset(normalizer.allowed_overrides):
            raise RegistryError(f"{path}: {normalizer_id} defaults must remain overrideable")
    return tuple(parsed)


def _validate_normalization_compatibility(
    normalization: NormalizationIR,
    field_types: tuple[str, ...],
    shape: str,
    path: str,
) -> None:
    kind = normalization.id.removesuffix("-v1").replace("-", "_")
    types = set(field_types)
    scalar_strings = {"string", "string[]"}
    numeric = {"int64", "uint32", "double", "int64[]", "double[]"}
    if kind == "identity":
        compatible = bool(types) and types.issubset({"boolean", "boolean[]"})
    elif kind == "bounded":
        compatible = bool(types) and types.issubset(scalar_strings | {"bytes"})
    elif kind in {"enum", "identifier"}:
        compatible = bool(types) and types.issubset(scalar_strings)
    elif kind == "numeric_range":
        compatible = bool(types) and types.issubset(numeric)
    elif kind in {"structured_content", "redacted_content"}:
        compatible = shape in {"any_value", "indexed_prefix", "object_prefix"} or (
            bool(types) and types.issubset({"string", "string[]", "bytes", "object", "array"})
        )
    elif kind in {"path", "url", "digest"}:
        compatible = types == {"string"}
    else:
        compatible = False
    if not compatible:
        raise RegistryError(f"{path}.id: {normalization.id} is incompatible with types={sorted(types)} shape={shape}")
    effective = normalization.effective_constraints
    if "enum" in effective:
        string_types = {"string", "string[]"}
        numeric_types = {"int64", "uint32", "double", "int64[]", "double[]"}
        for value in effective["enum"]:
            compatible = (
                (type(value) is str and bool(types & string_types))
                or (type(value) is bool and bool(types & {"boolean", "boolean[]"}))
                or (type(value) is int and bool(types & numeric_types))
                or (type(value) is float and bool(types & {"double", "double[]"}))
            )
            if not compatible:
                raise RegistryError(f"{path}.overrides.enum: member type is incompatible with attribute types")
    if kind == "enum" and "enum" not in effective:
        raise RegistryError(f"{path}.overrides.enum: required for enum-v1")
    if kind == "numeric_range":
        if not {"min", "max"}.issubset(effective):
            raise RegistryError(f"{path}.overrides: numeric-range-v1 requires min and max")
        if types & {"int64", "uint32", "int64[]"} and any(type(effective[key]) is not int for key in ("min", "max")):
            raise RegistryError(f"{path}.overrides: integer bounds must be exact integers")
    if kind in {"structured_content", "redacted_content"}:
        required = {
            "max_utf8_bytes",
            "max_item_utf8_bytes",
            "max_items",
            "max_depth",
            "max_properties",
        }
        if not required.issubset(effective):
            raise RegistryError(f"{path}: structured normalizer lacks mandatory bounds")
    if types & {"string[]"} and ("max_items" not in effective or "max_item_utf8_bytes" not in effective):
        raise RegistryError(f"{path}: string arrays require item-count and per-item byte bounds")
    if types & {"boolean[]", "int64[]", "double[]"} and "max_items" not in effective:
        raise RegistryError(f"{path}: arrays require an explicit max_items bound")
    collection_or_structured = shape in {"any_value", "indexed_prefix", "object_prefix"} or bool(
        types & {"string[]", "boolean[]", "int64[]", "double[]", "object", "array"}
    )
    if "min_items" in effective and not collection_or_structured:
        raise RegistryError(f"{path}: min_items requires an array or structured value")
    if effective.get("min_items", 0) > 1 and (shape == "any_value" or "canonical_json" in types):
        raise RegistryError(f"{path}: min_items greater than one is unsupported for polymorphic JSON")


def _parse_normalization(
    value: Any,
    path: str,
    normalizers: dict[str, NormalizerIR],
    *,
    field_types: tuple[str, ...] | None = None,
    shape: str = "attribute",
) -> NormalizationIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(value, {"id"}, {"overrides", "notes"}, path)
    normalizer_id = _string(value["id"], f"{path}.id", pattern=_ID)
    catalog = normalizers.get(normalizer_id)
    if catalog is None:
        raise RegistryError(f"{path}.id: unknown normalizer")
    overrides = _validate_constraint_map(value.get("overrides", {}), f"{path}.overrides")
    disallowed = overrides.keys() - set(catalog.allowed_overrides)
    if disallowed:
        raise RegistryError(f"{path}.overrides: disallowed keys {sorted(disallowed)}")
    notes = None
    if "notes" in value:
        notes = _string(value["notes"], f"{path}.notes")
    effective = dict(catalog.default_constraints)
    effective.update(overrides)
    _validate_constraint_map(effective, f"{path}.effective_constraints")
    normalization = NormalizationIR(
        normalizer_id,
        _freeze_mapping(overrides),
        _freeze_mapping(effective),
        notes,
    )
    if field_types is not None:
        _validate_normalization_compatibility(normalization, field_types, shape, path)
    return normalization


def _parse_structured_scalar(
    value: Any,
    path: str,
    normalizers: dict[str, NormalizerIR],
) -> StructuredScalarIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(value, {"type", "field_class", "sensitivity", "normalization"}, set(), path)
    field_type = _string(value["type"], f"{path}.type", pattern=_ID)
    if field_type not in {"boolean", "int64", "double", "string"}:
        raise RegistryError(f"{path}.type: unsupported structured scalar type")
    field_class = _string(value["field_class"], f"{path}.field_class")
    sensitivity = _string(value["sensitivity"], f"{path}.sensitivity")
    if field_class not in _FIELD_CLASS or sensitivity not in _SENSITIVITY:
        raise RegistryError(f"{path}: invalid structured scalar privacy")
    normalization = _parse_normalization(
        value["normalization"],
        f"{path}.normalization",
        normalizers,
        field_types=(field_type,),
    )
    return StructuredScalarIR(field_type, field_class, sensitivity, normalization, None, ())


def _parse_structured_reference(value: Any, path: str) -> StructuredReferenceIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(value, {"structured_ref"}, set(), path)
    return StructuredReferenceIR(_string(value["structured_ref"], f"{path}.structured_ref", pattern=_ID))


def _parse_structured_field(
    value: Any,
    path: str,
    normalizers: dict[str, NormalizerIR],
) -> StructuredFieldIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    required = {"name", "required"}
    scalar_keys = {"type", "field_class", "sensitivity", "normalization"}
    reference_keys = {"structured_ref"}
    keys = set(value)
    if keys == required | scalar_keys:
        name = _string(value["name"], f"{path}.name", pattern=_ID)
        if type(value["required"]) is not bool:
            raise RegistryError(f"{path}.required: expected boolean")
        scalar = _parse_structured_scalar({key: value[key] for key in scalar_keys}, path, normalizers)
        return StructuredFieldIR(name, value["required"], False, scalar, None)
    if keys == required | reference_keys:
        name = _string(value["name"], f"{path}.name", pattern=_ID)
        if type(value["required"]) is not bool:
            raise RegistryError(f"{path}.required: expected boolean")
        reference = _parse_structured_reference({"structured_ref": value["structured_ref"]}, path)
        return StructuredFieldIR(name, value["required"], False, None, reference)
    raise RegistryError(f"{path}: expected exactly one structured field arm")


def _parse_structured_dynamic_name(
    value: Any,
    path: str,
    normalizers: dict[str, NormalizerIR],
) -> StructuredDynamicNameIR:
    scalar = _parse_structured_scalar(value, path, normalizers)
    if scalar.field_type != "string":
        raise RegistryError(f"{path}.type: dynamic member names must be strings")
    return StructuredDynamicNameIR(
        scalar.field_type,
        scalar.field_class,
        scalar.sensitivity,
        scalar.normalization,
    )


def _parse_structured_dynamic_members(
    value: Any,
    path: str,
    normalizers: dict[str, NormalizerIR],
) -> StructuredDynamicMembersIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(
        value,
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
        },
        set(),
        path,
    )
    member_id = _string(value["member_id"], f"{path}.member_id", pattern=_ID)
    name = _parse_structured_dynamic_name(value["name"], f"{path}.name", normalizers)
    reference = _parse_structured_reference(value["value"], f"{path}.value")
    max_items = _integer(value["max_items"], f"{path}.max_items", minimum=1)
    policies = tuple(
        _string(value[key], f"{path}.{key}")
        for key in (
            "duplicate_name_policy",
            "fixed_name_collision_policy",
            "post_redaction_name_collision_policy",
        )
    )
    if (
        member_id != "entry"
        or name.field_class != "identifier"
        or name.sensitivity != "internal"
        or name.normalization.id != "bounded-v1"
        or name.normalization.effective_constraints.get("max_utf8_bytes") != 256
        or reference.structured_ref != "gen_ai.canonical_json"
        or max_items != 256
        or value["public_encoding"] != "ordered_typed_entries"
        or value["wire_encoding"] != "native_object_properties"
        or policies != ("reject", "reject", "reject")
    ):
        raise RegistryError(f"{path}: dynamic member contract differs from P-070")
    return StructuredDynamicMembersIR(
        member_id,
        name,
        reference,
        max_items,
        value["public_encoding"],
        value["wire_encoding"],
        *policies,
        (),
    )


def _parse_structured_discriminator(
    value: Any,
    path: str,
    normalizers: dict[str, NormalizerIR],
) -> StructuredDiscriminatorIR:
    expected_keys = {"name", "type", "field_class", "sensitivity", "normalization"}
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise RegistryError(f"{path}: invalid discriminator shape")
    name = _string(value["name"], f"{path}.name", pattern=_ID)
    scalar = _parse_structured_scalar(
        {key: value[key] for key in expected_keys - {"name"}},
        path,
        normalizers,
    )
    if scalar.field_type != "string":
        raise RegistryError(f"{path}.type: discriminator must be a string")
    return StructuredDiscriminatorIR(
        name,
        scalar.field_type,
        scalar.field_class,
        scalar.sensitivity,
        scalar.normalization,
    )


def _parse_canonical_json_contract(
    value: dict[str, Any],
    path: str,
    normalizers: dict[str, NormalizerIR],
) -> CanonicalJSONContractIR:
    _exact_keys(
        value,
        {"id", "kind", "introduced_in", "discriminator", "arms", "leaf_privacy", "array", "object", "limits"},
        set(),
        path,
    )
    discriminator = value["discriminator"]
    if not isinstance(discriminator, dict):
        raise RegistryError(f"{path}.discriminator: expected mapping")
    _exact_keys(discriminator, {"visibility", "wire"}, set(), f"{path}.discriminator")
    if discriminator != {"visibility": "internal", "wire": False}:
        raise RegistryError(f"{path}.discriminator: canonical discriminator must be internal and non-wire")
    arms = _string_list(value["arms"], f"{path}.arms", allow_empty=False)
    if arms != ("boolean", "int64", "finite_double", "string", "array", "object"):
        raise RegistryError(f"{path}.arms: canonical JSON arm inventory/order mismatch")
    privacy = value["leaf_privacy"]
    if not isinstance(privacy, dict):
        raise RegistryError(f"{path}.leaf_privacy: expected mapping")
    _exact_keys(privacy, {"field_class", "sensitivity"}, set(), f"{path}.leaf_privacy")
    if privacy != {"field_class": "content", "sensitivity": "sensitive"}:
        raise RegistryError(f"{path}.leaf_privacy: canonical JSON privacy mismatch")
    array = value["array"]
    if not isinstance(array, dict):
        raise RegistryError(f"{path}.array: expected mapping")
    _exact_keys(array, {"items_ref"}, set(), f"{path}.array")
    array_ref = _string(array["items_ref"], f"{path}.array.items_ref", pattern=_ID)
    object_value = value["object"]
    if not isinstance(object_value, dict):
        raise RegistryError(f"{path}.object: expected mapping")
    _exact_keys(
        object_value,
        {"members", "public_encoding", "wire_encoding"},
        set(),
        f"{path}.object",
    )
    members = object_value["members"]
    if not isinstance(members, dict):
        raise RegistryError(f"{path}.object.members: expected mapping")
    _exact_keys(members, {"member_id", "name", "value"}, set(), f"{path}.object.members")
    member_id = _string(members["member_id"], f"{path}.object.members.member_id", pattern=_ID)
    name = _parse_structured_dynamic_name(members["name"], f"{path}.object.members.name", normalizers)
    member_value = _parse_structured_reference(members["value"], f"{path}.object.members.value")
    limits_value = value["limits"]
    if not isinstance(limits_value, dict):
        raise RegistryError(f"{path}.limits: expected mapping")
    limit_keys = {
        "max_depth",
        "max_aggregate_members",
        "max_array_items",
        "max_string_utf8_bytes",
        "max_member_name_utf8_bytes",
        "max_item_bytes",
        "max_canonical_bytes",
    }
    _exact_keys(limits_value, limit_keys, set(), f"{path}.limits")
    parsed_limits = {key: _integer(limits_value[key], f"{path}.limits.{key}", minimum=1) for key in limit_keys}
    expected_limits = {
        "max_depth": 8,
        "max_aggregate_members": 256,
        "max_array_items": 256,
        "max_string_utf8_bytes": 4096,
        "max_member_name_utf8_bytes": 256,
        "max_item_bytes": 32768,
        "max_canonical_bytes": 65536,
    }
    if (
        array_ref != "gen_ai.canonical_json"
        or member_id != "entry"
        or name.field_class != "identifier"
        or name.sensitivity != "internal"
        or name.normalization.id != "bounded-v1"
        or name.normalization.effective_constraints.get("max_utf8_bytes") != 256
        or member_value.structured_ref != "gen_ai.canonical_json"
        or object_value["public_encoding"] != "ordered_typed_entries"
        or object_value["wire_encoding"] != "native_object_properties"
        or parsed_limits != expected_limits
    ):
        raise RegistryError(f"{path}: canonical JSON contract differs from P-070")
    return CanonicalJSONContractIR(
        "internal",
        False,
        arms,
        "content",
        "sensitive",
        array_ref,
        member_id,
        name,
        member_value,
        "ordered_typed_entries",
        "native_object_properties",
        "reject",
        "reject",
        "reject",
        CanonicalJSONLimitsIR(**parsed_limits),
    )


def _parse_structured_type(
    value: Any,
    path: str,
    normalizers: dict[str, NormalizerIR],
) -> StructuredTypeIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    kind = _string(value.get("kind"), f"{path}.kind", pattern=_ID)
    type_id = _string(value.get("id"), f"{path}.id", pattern=_ID)
    introduced_in = _string(value.get("introduced_in"), f"{path}.introduced_in")
    common = {"id", "kind", "introduced_in"}
    if introduced_in != "telemetry-registry-v1":
        raise RegistryError(f"{path}.introduced_in: expected telemetry-registry-v1")
    if kind == "canonical_json":
        contract = _parse_canonical_json_contract(value, path, normalizers)
        return StructuredTypeIR(
            id=type_id,
            kind=kind,
            introduced_in=introduced_in,
            additional_properties=None,
            fields=None,
            dynamic_members=None,
            items_scalar=None,
            items_reference=None,
            min_items=None,
            max_items=None,
            discriminator=None,
            variants=None,
            dynamic_variant=None,
            canonical_json=contract,
            effective_reserved_names=(),
        )
    if kind == "object":
        _exact_keys(value, common | {"additional_properties", "fields"}, {"dynamic_members"}, path)
        if value["additional_properties"] is not False:
            raise RegistryError(f"{path}.additional_properties: structured objects must be closed")
        raw_fields = value["fields"]
        if not isinstance(raw_fields, list):
            raise RegistryError(f"{path}.fields: expected sequence")
        fields = tuple(
            _parse_structured_field(item, f"{path}.fields[{index}]", normalizers)
            for index, item in enumerate(raw_fields)
        )
        names = tuple(item.name for item in fields)
        if len(names) != len(set(names)):
            raise RegistryError(f"{path}.fields: duplicate field name")
        dynamic = (
            _parse_structured_dynamic_members(value["dynamic_members"], f"{path}.dynamic_members", normalizers)
            if "dynamic_members" in value
            else None
        )
        if not fields and dynamic is None:
            raise RegistryError(f"{path}: empty object requires dynamic_members")
        if dynamic is not None:
            dynamic = replace(dynamic, reserved_names=tuple(sorted(names)))
        return StructuredTypeIR(
            id=type_id,
            kind=kind,
            introduced_in=introduced_in,
            additional_properties=False,
            fields=fields,
            dynamic_members=dynamic,
            items_scalar=None,
            items_reference=None,
            min_items=None,
            max_items=None,
            discriminator=None,
            variants=None,
            dynamic_variant=None,
            canonical_json=None,
            effective_reserved_names=tuple(sorted(names)),
        )
    if kind == "array":
        _exact_keys(value, common | {"items", "min_items", "max_items"}, set(), path)
        items = value["items"]
        if not isinstance(items, dict):
            raise RegistryError(f"{path}.items: expected mapping")
        if set(items) == {"structured_ref"}:
            item_scalar = None
            item_ref = _parse_structured_reference(items, f"{path}.items")
        elif set(items) == {"type", "field_class", "sensitivity", "normalization"}:
            item_scalar = _parse_structured_scalar(items, f"{path}.items", normalizers)
            item_ref = None
        else:
            raise RegistryError(f"{path}.items: expected exactly one item arm")
        min_items = _integer(value["min_items"], f"{path}.min_items", minimum=0)
        max_items = _integer(value["max_items"], f"{path}.max_items", minimum=1)
        if min_items > max_items:
            raise RegistryError(f"{path}: min_items exceeds max_items")
        return StructuredTypeIR(
            id=type_id,
            kind=kind,
            introduced_in=introduced_in,
            additional_properties=None,
            fields=None,
            dynamic_members=None,
            items_scalar=item_scalar,
            items_reference=item_ref,
            min_items=min_items,
            max_items=max_items,
            discriminator=None,
            variants=None,
            dynamic_variant=None,
            canonical_json=None,
            effective_reserved_names=(),
        )
    if kind == "tagged_union":
        _exact_keys(value, common | {"discriminator", "variants"}, {"dynamic_variant"}, path)
        discriminator = _parse_structured_discriminator(
            value["discriminator"],
            f"{path}.discriminator",
            normalizers,
        )
        raw_variants = value["variants"]
        if not isinstance(raw_variants, list) or len(raw_variants) < 2:
            raise RegistryError(f"{path}.variants: expected at least two variants")
        variants: list[StructuredVariantIR] = []
        for index, item in enumerate(raw_variants):
            item_path = f"{path}.variants[{index}]"
            if not isinstance(item, dict):
                raise RegistryError(f"{item_path}: expected mapping")
            _exact_keys(item, {"tag", "structured_ref"}, set(), item_path)
            variants.append(
                StructuredVariantIR(
                    _string(item["tag"], f"{item_path}.tag"),
                    _string(item["structured_ref"], f"{item_path}.structured_ref", pattern=_ID),
                )
            )
        tags = tuple(item.tag for item in variants)
        targets = tuple(item.structured_ref for item in variants)
        if len(tags) != len(set(tags)) or len(targets) != len(set(targets)):
            raise RegistryError(f"{path}.variants: tags and targets must be unique")
        dynamic: StructuredDynamicVariantIR | None = None
        if "dynamic_variant" in value:
            raw_dynamic = value["dynamic_variant"]
            dynamic_path = f"{path}.dynamic_variant"
            if not isinstance(raw_dynamic, dict):
                raise RegistryError(f"{dynamic_path}: expected mapping")
            _exact_keys(
                raw_dynamic,
                {"arm_id", "tag_normalization", "structured_ref", "exclude_registered_tags"},
                set(),
                dynamic_path,
            )
            normalization = _parse_normalization(
                raw_dynamic["tag_normalization"],
                f"{dynamic_path}.tag_normalization",
                normalizers,
                field_types=("string",),
            )
            if raw_dynamic["exclude_registered_tags"] is not True:
                raise RegistryError(f"{dynamic_path}.exclude_registered_tags: expected true")
            dynamic = StructuredDynamicVariantIR(
                _string(raw_dynamic["arm_id"], f"{dynamic_path}.arm_id", pattern=_ID),
                normalization,
                _string(raw_dynamic["structured_ref"], f"{dynamic_path}.structured_ref", pattern=_ID),
                True,
            )
            if normalization != discriminator.normalization:
                raise RegistryError(f"{dynamic_path}.tag_normalization: must equal discriminator normalization")
        return StructuredTypeIR(
            id=type_id,
            kind=kind,
            introduced_in=introduced_in,
            additional_properties=None,
            fields=None,
            dynamic_members=None,
            items_scalar=None,
            items_reference=None,
            min_items=None,
            max_items=None,
            discriminator=discriminator,
            variants=tuple(variants),
            dynamic_variant=dynamic,
            canonical_json=None,
            effective_reserved_names=(discriminator.name,),
        )
    raise RegistryError(f"{path}.kind: unsupported structured type kind")


def _structured_references(item: StructuredTypeIR) -> tuple[str, ...]:
    references: list[str] = []
    for field in item.fields or ():
        if field.reference is not None:
            references.append(field.reference.structured_ref)
    if item.dynamic_members is not None:
        references.append(item.dynamic_members.value.structured_ref)
    if item.items_reference is not None:
        references.append(item.items_reference.structured_ref)
    for variant in item.variants or ():
        references.append(variant.structured_ref)
    if item.dynamic_variant is not None:
        references.append(item.dynamic_variant.structured_ref)
    if item.canonical_json is not None:
        references.extend((item.canonical_json.array_items_ref, item.canonical_json.object_value.structured_ref))
    return tuple(references)


def _validate_structured_type_graph(items: tuple[StructuredTypeIR, ...], path: str) -> tuple[StructuredTypeIR, ...]:
    by_id = {item.id: item for item in items}
    if len(by_id) != len(items):
        raise RegistryError(f"{path}: duplicate structured type ID")
    if tuple(by_id) != EXPECTED_STRUCTURED_TYPE_IDS:
        raise RegistryError(f"{path}: structured type inventory/order mismatch")
    for item in items:
        for reference in _structured_references(item):
            if reference not in by_id:
                raise RegistryError(f"{path}: {item.id} has unknown structured_ref {reference}")
            if reference == item.id and item.id != "gen_ai.canonical_json":
                raise RegistryError(f"{path}: only gen_ai.canonical_json may self-reference")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(type_id: str) -> None:
        if type_id in visited:
            return
        if type_id in visiting:
            raise RegistryError(f"{path}: structured reference graph contains a cycle")
        visiting.add(type_id)
        for reference in _structured_references(by_id[type_id]):
            if type_id == reference == "gen_ai.canonical_json":
                continue
            visit(reference)
        visiting.remove(type_id)
        visited.add(type_id)

    for type_id in by_id:
        visit(type_id)

    reserved_by_target: dict[str, set[str]] = {item.id: set(item.effective_reserved_names) for item in items}
    for item in items:
        if item.discriminator is None:
            continue
        for target in (variant.structured_ref for variant in item.variants or ()):
            target_item = by_id[target]
            if target_item.kind != "object":
                raise RegistryError(f"{path}: tagged-union targets must be objects")
            if any(field.name == item.discriminator.name for field in target_item.fields or ()):
                raise RegistryError(f"{path}: discriminator collides with target fixed field")
            reserved_by_target[target].add(item.discriminator.name)
        if item.dynamic_variant is not None:
            target = item.dynamic_variant.structured_ref
            target_item = by_id[target]
            if target_item.kind != "object" or any(
                field.name == item.discriminator.name for field in target_item.fields or ()
            ):
                raise RegistryError(f"{path}: dynamic discriminator collides with target")
            reserved_by_target[target].add(item.discriminator.name)

    result: list[StructuredTypeIR] = []
    for item in items:
        reserved = tuple(sorted(reserved_by_target[item.id]))
        dynamic = item.dynamic_members
        if dynamic is not None:
            dynamic = replace(dynamic, reserved_names=reserved)
        result.append(replace(item, dynamic_members=dynamic, effective_reserved_names=reserved))
    return tuple(result)


def _parse_structured_types(
    value: Any,
    path: str,
    normalizers: dict[str, NormalizerIR],
) -> tuple[StructuredTypeIR, ...]:
    if not isinstance(value, list):
        raise RegistryError(f"{path}: expected sequence")
    parsed = tuple(_parse_structured_type(item, f"{path}[{index}]", normalizers) for index, item in enumerate(value))
    validated = _validate_structured_type_graph(parsed, path)
    by_id = {item.id: item for item in validated}
    canonical = by_id["gen_ai.canonical_json"]
    if canonical.kind != "canonical_json" or canonical.canonical_json is None:
        raise RegistryError(f"{path}: reserved canonical JSON type is invalid")
    for type_id, expected in EXPECTED_STRUCTURED_ARRAYS.items():
        item = by_id[type_id]
        observed = (
            None if item.items_reference is None else item.items_reference.structured_ref,
            item.min_items,
            item.max_items,
        )
        if item.kind != "array" or observed != expected:
            raise RegistryError(f"{path}: {type_id} array contract mismatch")
    union = by_id["gen_ai.message_part"]
    if (
        union.kind != "tagged_union"
        or union.discriminator is None
        or union.discriminator.name != "type"
        or union.discriminator.field_class != "identifier"
        or union.discriminator.sensitivity != "internal"
        or union.discriminator.normalization.id != "bounded-v1"
        or union.discriminator.normalization.overrides != {"max_utf8_bytes": 256}
        or union.discriminator.normalization.effective_constraints.get("max_utf8_bytes") != 256
        or "enum" in union.discriminator.normalization.effective_constraints
        or "pattern" in union.discriminator.normalization.effective_constraints
        or tuple((variant.tag, variant.structured_ref) for variant in union.variants or ())
        != EXPECTED_MESSAGE_PART_VARIANTS
        or union.dynamic_variant is None
        or union.dynamic_variant.arm_id != "generic"
        or union.dynamic_variant.structured_ref != "gen_ai.generic_part"
    ):
        raise RegistryError(f"{path}: gen_ai.message_part union contract mismatch")
    for type_id, expected_fields in EXPECTED_STRUCTURED_OBJECT_FIELDS.items():
        item = by_id[type_id]
        observed_fields = tuple(
            (
                field.name,
                field.required,
                "scalar" if field.scalar is not None else "reference",
                field.scalar.field_type if field.scalar is not None else field.reference.structured_ref,
            )
            for field in item.fields or ()
        )
        if item.kind != "object" or observed_fields != expected_fields or item.dynamic_members is None:
            raise RegistryError(f"{path}: {type_id} object contract mismatch")
    for (type_id, field_name), expected in AUDITED_STRUCTURED_SCALARS.items():
        field = next(field for field in by_id[type_id].fields or () if field.name == field_name)
        scalar = field.scalar
        observed = (
            None if scalar is None else scalar.field_class,
            None if scalar is None else scalar.sensitivity,
            None if scalar is None else scalar.normalization.id,
            None if scalar is None else scalar.normalization.effective_constraints.get("max_utf8_bytes"),
        )
        if observed != expected:
            raise RegistryError(f"{path}: {type_id}.{field_name} audited privacy/bound mismatch")
    for type_id, field_name in AUDITED_STRUCTURED_CONTENT_FIELDS:
        field = next(field for field in by_id[type_id].fields or () if field.name == field_name)
        scalar = field.scalar
        if (
            scalar is None
            or scalar.field_class != "content"
            or scalar.sensitivity != "sensitive"
            or scalar.normalization.id != "redacted-content-v1"
            or scalar.normalization.effective_constraints.get("max_item_utf8_bytes") != 4096
        ):
            raise RegistryError(f"{path}: {type_id}.{field_name} content privacy mismatch")
    materialized = _semantic_digest_projection(_materialize_registry_fact(validated))
    digest = hashlib.sha256(_canonical_json_bytes(_typed_materialized_node(materialized))).hexdigest()
    if digest != EXPECTED_AUTHORED_STRUCTURED_TYPES_SHA256:
        raise RegistryError(
            f"{path}: complete canonical contract digest mismatch "
            f"(expected {EXPECTED_AUTHORED_STRUCTURED_TYPES_SHA256}, observed {digest})"
        )
    return validated


def _parse_structured_bindings(
    value: Any,
    path: str,
    types: tuple[StructuredTypeIR, ...],
) -> tuple[StructuredBindingIR, ...]:
    if not isinstance(value, list):
        raise RegistryError(f"{path}: expected sequence")
    known_types = {item.id for item in types}
    result: list[StructuredBindingIR] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(
            item,
            {"attribute", "structured_type", "public_encoding", "canonical_wire_encoding"},
            set(),
            item_path,
        )
        binding = StructuredBindingIR(
            _string(item["attribute"], f"{item_path}.attribute", pattern=_ID),
            _string(item["structured_type"], f"{item_path}.structured_type", pattern=_ID),
            _string(item["public_encoding"], f"{item_path}.public_encoding", pattern=_ID),
            _string(item["canonical_wire_encoding"], f"{item_path}.canonical_wire_encoding", pattern=_ID),
        )
        if binding.structured_type not in known_types:
            raise RegistryError(f"{item_path}.structured_type: unknown structured type")
        result.append(binding)
    observed = tuple(
        (item.attribute, item.structured_type, item.public_encoding, item.canonical_wire_encoding) for item in result
    )
    if observed != EXPECTED_STRUCTURED_BINDINGS:
        raise RegistryError(f"{path}: structured binding inventory/order mismatch")
    return tuple(result)


def _schema_allows_null(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    if value.get("type") == "null":
        return True
    any_of = value.get("anyOf")
    if isinstance(any_of, list) and any(_schema_allows_null(item) for item in any_of):
        return True
    return (
        value.get("default", object()) is None and "type" not in value and "$ref" not in value and "anyOf" not in value
    )


def _json_pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _expected_source_fields(type_id: str) -> tuple[tuple[str, bool, str, str], ...]:
    fields = tuple(
        (
            name,
            STRUCTURED_SOURCE_REQUIRED_OVERRIDES.get((type_id, name), required),
            arm,
            target,
        )
        for name, required, arm, target in EXPECTED_STRUCTURED_OBJECT_FIELDS[type_id]
    )
    if type_id in {target for _, target in EXPECTED_MESSAGE_PART_VARIANTS} or type_id == "gen_ai.generic_part":
        return (("type", True, "discriminator", "string"), *fields)
    return fields


def _validate_source_property_shape(
    schema: Any,
    *,
    type_id: str,
    field_name: str,
    arm: str,
    target: str,
    path: str,
) -> None:
    if not isinstance(schema, dict):
        raise RegistryError(f"{path}: expected property schema object")
    if arm == "discriminator":
        if type_id == "gen_ai.generic_part":
            _exact_keys(schema, {"type"}, {"description", "title"}, path)
            if schema.get("type") != "string" or "const" in schema:
                raise RegistryError(f"{path}: GenericPart discriminator must remain open")
        else:
            _exact_keys(schema, {"const", "type"}, {"description", "title"}, path)
            expected_tag = next(tag for tag, ref in EXPECTED_MESSAGE_PART_VARIANTS if ref == type_id)
            if schema.get("type") != "string" or schema.get("const") != expected_tag:
                raise RegistryError(f"{path}: registered discriminator tag mismatch")
        return
    if arm == "scalar":
        if target != "string":
            raise RegistryError(f"{path}: unsupported source scalar expectation")
        variants = schema.get("anyOf")
        if variants is not None:
            _exact_keys(schema, {"anyOf"}, {"default", "description", "title"}, path)
            if not isinstance(variants, list) or not variants:
                raise RegistryError(f"{path}.anyOf: expected nonempty sequence")
            for index, item in enumerate(variants):
                branch_path = f"{path}.anyOf[{index}]"
                if not isinstance(item, dict) or set(item) not in ({"type"}, {"$ref"}):
                    raise RegistryError(f"{branch_path}: unsupported schema surface")
            nullable = field_name in STRUCTURED_NULLABLE_OPTIONALS.get(type_id, frozenset())
            enum_ref = {
                "role": "Role",
                "modality": "Modality",
                "finish_reason": "FinishReason",
            }.get(field_name)
            if nullable:
                if (
                    variants != [{"type": "string"}, {"type": "null"}]
                    or "default" not in schema
                    or schema["default"] is not None
                ):
                    raise RegistryError(f"{path}.anyOf: nullable string contract changed")
            elif enum_ref is not None:
                if variants != [{"$ref": f"#/$defs/{enum_ref}"}, {"type": "string"}] or "default" in schema:
                    raise RegistryError(f"{path}.anyOf: open enum string contract changed")
            else:
                raise RegistryError(f"{path}.anyOf: unexpected scalar union")
        else:
            _exact_keys(schema, {"type"}, {"description", "format", "title"}, path)
            binary_content = type_id == "gen_ai.blob_part" and field_name == "content"
            if binary_content != (schema.get("format") == "binary") or (
                "format" in schema and schema["format"] != "binary"
            ):
                raise RegistryError(f"{path}.format: source string format contract changed")
        scalar_ok = schema.get("type") == "string" or (
            isinstance(variants, list)
            and any(isinstance(item, dict) and item.get("type") == "string" for item in variants)
        )
        if not scalar_ok:
            raise RegistryError(f"{path}: expected string-compatible property")
        return
    if field_name == "parts":
        _exact_keys(schema, {"items", "type"}, {"description", "title"}, path)
        if schema.get("type") != "array" or not isinstance(schema.get("items"), dict):
            raise RegistryError(f"{path}: message parts must remain an array")
        _exact_keys(schema["items"], {"anyOf"}, set(), f"{path}.items")
        any_of = schema["items"].get("anyOf")
        expected_refs = tuple(
            f"#/$defs/{name}"
            for name in (
                "TextPart",
                "ToolCallRequestPart",
                "ToolCallResponsePart",
                "ServerToolCallPart",
                "ServerToolCallResponsePart",
                "BlobPart",
                "FilePart",
                "UriPart",
                "ReasoningPart",
                "CompactionPart",
                "GenericPart",
            )
        )
        if isinstance(any_of, list):
            for index, item in enumerate(any_of):
                if not isinstance(item, dict) or set(item) != {"$ref"}:
                    raise RegistryError(f"{path}.items.anyOf[{index}]: unsupported union branch surface")
        observed_refs = tuple(item.get("$ref") for item in any_of) if isinstance(any_of, list) else ()
        if observed_refs != expected_refs:
            raise RegistryError(f"{path}: message-part union inventory/order mismatch")
        return
    expected_ref_by_field = {
        "server_tool_call": "#/$defs/GenericServerToolCall",
        "server_tool_call_response": "#/$defs/GenericServerToolCallResponse",
    }
    if field_name in expected_ref_by_field:
        _exact_keys(schema, {"$ref"}, {"description"}, path)
        if schema.get("$ref") != expected_ref_by_field[field_name]:
            raise RegistryError(f"{path}: server-tool payload reference mismatch")
        return
    if field_name not in {"arguments", "response"}:
        raise RegistryError(f"{path}: unrecognized structured reference property")
    semantic_keys = set(schema) - {"default", "description", "title"}
    if semantic_keys:
        raise RegistryError(f"{path}: tool payload must remain unconstrained any JSON")


def _validate_message_structural_input(
    input_path: str,
    document: dict[str, Any],
    types_by_id: Mapping[str, StructuredTypeIR],
) -> tuple[StructuredPropertyDispositionIR, ...]:
    expected_root = {
        "model/gen-ai/gen-ai-input-messages.json": ("InputMessages", "#/$defs/ChatMessage", "gen_ai.input_messages"),
        "model/gen-ai/gen-ai-output-messages.json": (
            "OutputMessages",
            "#/$defs/OutputMessage",
            "gen_ai.output_messages",
        ),
    }[input_path]
    if set(document) != {"$defs", "description", "items", "title", "type"}:
        raise RegistryError(f"{input_path}: message schema root surface changed")
    if (
        document["title"] != expected_root[0]
        or document["type"] != "array"
        or document["items"] != {"$ref": expected_root[1]}
    ):
        raise RegistryError(f"{input_path}: message schema root changed")
    definitions = document["$defs"]
    if not isinstance(definitions, dict):
        raise RegistryError(f"{input_path}#/$defs: expected mapping")
    definition_map = STRUCTURED_SOURCE_DEFINITIONS[input_path]
    scalar_definitions = {"Modality", "Role"}
    if "OutputMessage" in definition_map:
        scalar_definitions.add("FinishReason")
    if set(definitions) != set(definition_map) | scalar_definitions:
        raise RegistryError(f"{input_path}#/$defs: definition inventory changed")
    for name in scalar_definitions:
        definition = definitions[name]
        if not isinstance(definition, dict) or definition.get("type") != "string":
            raise RegistryError(f"{input_path}#/$defs/{name}: scalar definition changed")
        _exact_keys(
            definition,
            {"enum", "type"},
            {"description", "title"},
            f"{input_path}#/$defs/{name}",
        )
        if tuple(definition.get("enum", ())) != EXPECTED_STRUCTURAL_SOURCE_ENUMS[name]:
            raise RegistryError(f"{input_path}#/$defs/{name}: enum changed")

    dispositions: list[StructuredPropertyDispositionIR] = []
    open_surfaces = 0
    property_occurrences = 0
    for definition_name in sorted(definition_map):
        type_id = definition_map[definition_name]
        definition_path = f"{input_path}#/$defs/{definition_name}"
        definition = definitions[definition_name]
        if not isinstance(definition, dict) or definition.get("type") != "object":
            raise RegistryError(f"{definition_path}: expected object definition")
        required_definition_keys = {"properties", "required", "type"}
        if definition_name != "BlobPart":
            required_definition_keys.add("additionalProperties")
        _exact_keys(
            definition,
            required_definition_keys,
            {"description", "title"},
            definition_path,
        )
        properties = definition.get("properties")
        required = definition.get("required")
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise RegistryError(f"{definition_path}: object properties/required changed")
        expected_fields = _expected_source_fields(type_id)
        expected_names = tuple(field[0] for field in expected_fields)
        expected_required = tuple(field[0] for field in expected_fields if field[1])
        if tuple(properties) != expected_names or tuple(required) != expected_required:
            raise RegistryError(f"{definition_path}: property inventory/order changed")
        if definition_name != "BlobPart" and definition["additionalProperties"] is not True:
            raise RegistryError(f"{definition_path}: open-object surface was closed")
        open_surfaces += 1
        dynamic_pointer = (
            f"#/$defs/{_json_pointer_token(definition_name)}"
            if definition_name == "BlobPart"
            else f"#/$defs/{_json_pointer_token(definition_name)}/additionalProperties"
        )
        dispositions.append(
            StructuredPropertyDispositionIR(
                input_path,
                dynamic_pointer,
                "dynamic_members",
                type_id,
                None,
                None,
                None,
            )
        )
        type_fields = {field.name: field for field in types_by_id[type_id].fields or ()}
        nullable_names = STRUCTURED_NULLABLE_OPTIONALS.get(type_id, frozenset())
        for field_name, is_required, arm, target in expected_fields:
            property_occurrences += 1
            property_path = f"{definition_path}/properties/{field_name}"
            schema = properties[field_name]
            _validate_source_property_shape(
                schema,
                type_id=type_id,
                field_name=field_name,
                arm=arm,
                target=target,
                path=property_path,
            )
            if field_name == "type":
                if type_id == "gen_ai.generic_part":
                    disposition = "dynamic_variant"
                    disposition_type = "gen_ai.message_part"
                    arm_id = "generic"
                elif type_id in {target for _, target in EXPECTED_MESSAGE_PART_VARIANTS}:
                    disposition = "fixed_field"
                    disposition_type = "gen_ai.message_part"
                    arm_id = next(tag for tag, target in EXPECTED_MESSAGE_PART_VARIANTS if target == type_id)
                else:
                    disposition = "fixed_field"
                    disposition_type = type_id
                    arm_id = None
                target_type = type_id if disposition_type == "gen_ai.message_part" else None
            else:
                target_field = type_fields.get(field_name)
                required_override = STRUCTURED_SOURCE_REQUIRED_OVERRIDES.get((type_id, field_name))
                if (
                    target_field is None
                    or (target_field.required is not is_required and required_override is None)
                    or (required_override is not None and required_override is not is_required)
                ):
                    raise RegistryError(f"{property_path}: authored structured field mismatch")
                if arm == "scalar":
                    if target_field.scalar is None or target_field.scalar.field_type != target:
                        raise RegistryError(f"{property_path}: authored scalar field mismatch")
                elif target_field.reference is None or target_field.reference.structured_ref != target:
                    raise RegistryError(f"{property_path}: authored structured reference mismatch")
                nullable = field_name in nullable_names
                if nullable != (not is_required and _schema_allows_null(schema)):
                    raise RegistryError(f"{property_path}: nullable-optional disposition changed")
                disposition = "nullable_optional_omission" if nullable else "fixed_field"
                disposition_type = type_id
                arm_id = None
                target_type = None
            dispositions.append(
                StructuredPropertyDispositionIR(
                    input_path,
                    f"#/$defs/{_json_pointer_token(definition_name)}/properties/{_json_pointer_token(field_name)}",
                    disposition,
                    disposition_type,
                    field_name,
                    arm_id,
                    target_type,
                )
            )
    expected_occurrences = 39 if "ChatMessage" in definition_map else 40
    if property_occurrences != expected_occurrences or open_surfaces != 14:
        raise RegistryError(f"{input_path}: property/open-surface inventory changed")
    return tuple(dispositions)


def _validate_tool_structural_input(
    input_path: str,
    document: dict[str, Any],
    type_id: str,
) -> tuple[StructuredPropertyDispositionIR, ...]:
    if set(document) != {"additionalProperties", "description", "title", "type"}:
        raise RegistryError(f"{input_path}: tool object schema surface changed")
    if document["type"] != "object" or document["additionalProperties"] is not True:
        raise RegistryError(f"{input_path}: tool root must remain an open object")
    return (
        StructuredPropertyDispositionIR(
            input_path,
            "#/additionalProperties",
            "dynamic_members",
            type_id,
            None,
            None,
            None,
        ),
    )


def _validate_structural_inputs(
    documents: Mapping[str, dict[str, Any]],
    types: tuple[StructuredTypeIR, ...],
) -> tuple[tuple[StructuredTypeIR, ...], tuple[StructuredPropertyDispositionIR, ...]]:
    if tuple(documents) != tuple(item[0] for item in EXPECTED_STRUCTURAL_INPUTS):
        raise RegistryError("structural inputs: parsed document inventory/order mismatch")
    by_id = {item.id: item for item in types}
    dispositions = (
        *_validate_message_structural_input(
            "model/gen-ai/gen-ai-input-messages.json",
            documents["model/gen-ai/gen-ai-input-messages.json"],
            by_id,
        ),
        *_validate_message_structural_input(
            "model/gen-ai/gen-ai-output-messages.json",
            documents["model/gen-ai/gen-ai-output-messages.json"],
            by_id,
        ),
        *_validate_tool_structural_input(
            "model/gen-ai/gen-ai-tool-call-arguments.json",
            documents["model/gen-ai/gen-ai-tool-call-arguments.json"],
            "gen_ai.tool_call_arguments",
        ),
        *_validate_tool_structural_input(
            "model/gen-ai/gen-ai-tool-call-result.json",
            documents["model/gen-ai/gen-ai-tool-call-result.json"],
            "gen_ai.tool_call_result",
        ),
    )
    nullable_by_type = {type_id: names for type_id, names in STRUCTURED_NULLABLE_OPTIONALS.items()}
    updated: list[StructuredTypeIR] = []
    for item in types:
        if item.fields is None:
            updated.append(item)
            continue
        nullable = nullable_by_type.get(item.id, frozenset())
        enriched_fields: list[StructuredFieldIR] = []
        for field in item.fields:
            scalar = field.scalar
            encoding_annotation = (
                "json-base64-bytes-v1" if item.id == "gen_ai.blob_part" and field.name == "content" else None
            )
            known_values: tuple[str, ...] = ()
            if field.name == "role":
                known_values = EXPECTED_STRUCTURAL_SOURCE_ENUMS["Role"]
            elif field.name == "modality":
                known_values = EXPECTED_STRUCTURAL_SOURCE_ENUMS["Modality"]
            elif field.name == "finish_reason":
                known_values = EXPECTED_STRUCTURAL_SOURCE_ENUMS["FinishReason"]
            if scalar is not None and known_values:
                scalar = replace(scalar, known_values=known_values)
            if scalar is not None:
                scalar = replace(scalar, encoding_annotation=encoding_annotation)
            enriched_fields.append(
                replace(
                    field,
                    nullable_omission=field.name in nullable,
                    scalar=scalar,
                )
            )
        updated.append(
            replace(
                item,
                fields=tuple(enriched_fields),
            )
        )
    return tuple(updated), tuple(dispositions)


def _parse_conditions(value: Any, path: str) -> tuple[ConditionIR, ...]:
    if not isinstance(value, list) or not value:
        raise RegistryError(f"{path}: expected nonempty sequence")
    result: list[ConditionIR] = []
    seen_ids: set[str] = set()
    seen_facts: set[str] = set()
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(item, {"id", "description", "enforcement", "false_requirement"}, set(), item_path)
        condition_id = _string(item["id"], f"{item_path}.id", pattern=_ID)
        if condition_id in seen_ids:
            raise RegistryError(f"{path}: duplicate condition ID")
        description = _string(item["description"], f"{item_path}.description")
        enforcement = item["enforcement"]
        if not isinstance(enforcement, dict):
            raise RegistryError(f"{item_path}.enforcement: expected mapping")
        _exact_keys(enforcement, {"kind"}, {"fact", "attribute"}, f"{item_path}.enforcement")
        kind = _string(enforcement["kind"], f"{item_path}.enforcement.kind", pattern=_ID)
        fact: str | None = None
        attribute: str | None = None
        if kind == "builder_fact":
            if set(enforcement) != {"kind", "fact"}:
                raise RegistryError(f"{item_path}.enforcement: builder_fact requires only fact")
            fact = _string(enforcement["fact"], f"{item_path}.enforcement.fact", pattern=_ID)
            if fact in seen_facts:
                raise RegistryError(f"{path}: duplicate builder fact")
            seen_facts.add(fact)
        elif kind == "boolean_attribute":
            if set(enforcement) != {"kind", "attribute"}:
                raise RegistryError(f"{item_path}.enforcement: boolean_attribute requires only attribute")
            attribute = _string(enforcement["attribute"], f"{item_path}.enforcement.attribute", pattern=_ID)
        else:
            raise RegistryError(f"{item_path}.enforcement.kind: unsupported value")
        false_requirement = _string(
            item["false_requirement"],
            f"{item_path}.false_requirement",
            pattern=_ID,
        )
        if false_requirement not in {"forbidden", "optional"}:
            raise RegistryError(f"{item_path}.false_requirement: unsupported value")
        result.append(
            ConditionIR(
                condition_id,
                description,
                ConditionEnforcementIR(kind, fact, attribute),
                false_requirement,
            )
        )
        seen_ids.add(condition_id)
    return tuple(result)


def _parse_mandatory_rule_catalog(value: Any, path: str) -> MandatoryRuleCatalogIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(value, {"version", "rules"}, set(), path)
    version = _integer(value["version"], f"{path}.version")
    if version != 1:
        raise RegistryError(f"{path}.version: unsupported version")
    raw_rules = value["rules"]
    if not isinstance(raw_rules, list):
        raise RegistryError(f"{path}.rules: expected sequence")
    rules: list[MandatoryRuleIR] = []
    seen_ids: set[str] = set()
    seen_facts: set[str] = set()
    for index, raw_rule in enumerate(raw_rules):
        rule_path = f"{path}.rules[{index}]"
        if not isinstance(raw_rule, dict):
            raise RegistryError(f"{rule_path}: expected mapping")
        _exact_keys(raw_rule, {"id", "enforcement"}, set(), rule_path)
        rule_id = _string(raw_rule["id"], f"{rule_path}.id", pattern=_ID)
        if rule_id in seen_ids:
            raise RegistryError(f"{path}.rules: duplicate rule ID")
        raw_enforcement = raw_rule["enforcement"]
        if not isinstance(raw_enforcement, dict):
            raise RegistryError(f"{rule_path}.enforcement: expected mapping")
        kind = _string(raw_enforcement.get("kind"), f"{rule_path}.enforcement.kind", pattern=_ID)
        if kind == "constant":
            _exact_keys(raw_enforcement, {"kind", "value"}, set(), f"{rule_path}.enforcement")
            if raw_enforcement["value"] is not True:
                raise RegistryError(f"{rule_path}.enforcement.value: constant rule must be true")
            enforcement = MandatoryRuleEnforcementIR(kind, True, None)
        elif kind == "builder_fact":
            _exact_keys(raw_enforcement, {"kind", "fact"}, set(), f"{rule_path}.enforcement")
            fact = _string(raw_enforcement["fact"], f"{rule_path}.enforcement.fact", pattern=_ID)
            if fact in seen_facts:
                raise RegistryError(f"{path}.rules: duplicate builder fact")
            seen_facts.add(fact)
            enforcement = MandatoryRuleEnforcementIR(kind, None, fact)
        else:
            raise RegistryError(f"{rule_path}.enforcement.kind: unsupported value")
        rules.append(MandatoryRuleIR(rule_id, enforcement))
        seen_ids.add(rule_id)
    observed = tuple(
        (
            rule.id,
            rule.enforcement.kind,
            rule.enforcement.value if rule.enforcement.kind == "constant" else rule.enforcement.fact,
        )
        for rule in rules
    )
    if observed != _MANDATORY_RULE_CATALOG_V1:
        raise RegistryError(f"{path}: version 1 rule catalog does not match the exact required inventory")
    return MandatoryRuleCatalogIR(version, tuple(rules))


def _parse_value_catalogs(value: Any, path: str) -> tuple[ValueCatalogIR, ...]:
    if not isinstance(value, list) or not value:
        raise RegistryError(f"{path}: expected nonempty sequence")
    catalogs: list[ValueCatalogIR] = []
    seen_catalogs: set[str] = set()
    for catalog_index, item in enumerate(value):
        item_path = f"{path}[{catalog_index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(
            item,
            {
                "id",
                "kind",
                "value_attributes",
                "paired_value_attribute",
                "code_attribute",
                "entries",
                "compatibility",
            },
            set(),
            item_path,
        )
        catalog_id = _string(item["id"], f"{item_path}.id", pattern=_ID)
        if catalog_id in seen_catalogs:
            raise RegistryError(f"{path}: duplicate value catalog ID")
        kind = _string(item["kind"], f"{item_path}.kind", pattern=_ID)
        if kind != "string-int64-bijection":
            raise RegistryError(f"{item_path}.kind: unsupported value catalog kind")
        value_attributes = _string_list(
            item["value_attributes"],
            f"{item_path}.value_attributes",
            allow_empty=False,
        )
        paired_value_attribute = _string(
            item["paired_value_attribute"],
            f"{item_path}.paired_value_attribute",
            pattern=_ID,
        )
        if paired_value_attribute not in value_attributes:
            raise RegistryError(f"{item_path}.paired_value_attribute: must name a value attribute")
        code_attribute = _string(item["code_attribute"], f"{item_path}.code_attribute", pattern=_ID)
        if code_attribute in value_attributes:
            raise RegistryError(f"{item_path}.code_attribute: must differ from value attributes")
        entries_raw = item["entries"]
        if not isinstance(entries_raw, list) or not entries_raw:
            raise RegistryError(f"{item_path}.entries: expected nonempty sequence")
        entries: list[ValueCatalogEntryIR] = []
        seen_values: set[str] = set()
        seen_codes: set[int] = set()
        for index, entry in enumerate(entries_raw):
            entry_path = f"{item_path}.entries[{index}]"
            if not isinstance(entry, dict):
                raise RegistryError(f"{entry_path}: expected mapping")
            _exact_keys(entry, {"value", "code"}, set(), entry_path)
            entry_value = _string(entry["value"], f"{entry_path}.value", pattern=_ID)
            entry_code = _integer(entry["code"], f"{entry_path}.code")
            if entry_value in seen_values or entry_code in seen_codes:
                raise RegistryError(f"{item_path}.entries: values and codes must be bijective")
            if entry_code != index + 1:
                raise RegistryError(f"{entry_path}.code: codes must be contiguous positive integers")
            entries.append(ValueCatalogEntryIR(entry_value, entry_code))
            seen_values.add(entry_value)
            seen_codes.add(entry_code)
        compatibility = item["compatibility"]
        if not isinstance(compatibility, dict):
            raise RegistryError(f"{item_path}.compatibility: expected mapping")
        _exact_keys(
            compatibility,
            {"value", "code", "canonical_emittable"},
            set(),
            f"{item_path}.compatibility",
        )
        compatibility_value = _string(
            compatibility["value"],
            f"{item_path}.compatibility.value",
            pattern=_ID,
        )
        compatibility_code = _integer(
            compatibility["code"],
            f"{item_path}.compatibility.code",
            minimum=0,
        )
        if compatibility_code != 0 or compatibility_value in seen_values:
            raise RegistryError(f"{item_path}.compatibility: code zero must reserve a noncanonical value")
        if compatibility["canonical_emittable"] is not False:
            raise RegistryError(f"{item_path}.compatibility.canonical_emittable: must be false")
        catalogs.append(
            ValueCatalogIR(
                catalog_id,
                kind,
                value_attributes,
                paired_value_attribute,
                code_attribute,
                tuple(entries),
                ValueCatalogCompatibilityIR(compatibility_value, compatibility_code, False),
            )
        )
        seen_catalogs.add(catalog_id)
    return tuple(catalogs)


def _parse_structural_field(
    value: Any,
    path: str,
    normalizers: dict[str, NormalizerIR],
) -> StructuralFieldIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(
        value,
        {"name", "type", "required"},
        {
            "const",
            "enum",
            "object_ref",
            "item_ref",
            "semantic_ref",
            "semantic_format",
            "field_class",
            "sensitivity",
            "normalization",
            "otlp",
        },
        path,
    )
    name = _string(value["name"], f"{path}.name")
    field_type = _string(value["type"], f"{path}.type")
    if field_type not in _STRUCTURAL_FIELD_TYPE:
        raise RegistryError(f"{path}.type: unsupported structural field type")
    if type(value["required"]) is not bool:
        raise RegistryError(f"{path}.required: expected boolean")
    const_present = "const" in value
    const = None
    if const_present:
        _validate_json_compatible(value["const"], f"{path}.const")
        const = _freeze_json(value["const"])
    enum: tuple[FrozenJSON, ...] = ()
    if "enum" in value:
        if not isinstance(value["enum"], list) or not value["enum"]:
            raise RegistryError(f"{path}.enum: expected nonempty sequence")
        for index, item in enumerate(value["enum"]):
            _validate_json_compatible(item, f"{path}.enum[{index}]")
        enum = tuple(_freeze_json(item) for item in value["enum"])
        if len(enum) != len(set(enum)):
            raise RegistryError(f"{path}.enum: duplicate value")
    if const_present and enum:
        raise RegistryError(f"{path}: const and enum are mutually exclusive")

    def value_matches_type(item: FrozenJSON) -> bool:
        if field_type in {"string", "timestamp"}:
            return isinstance(item, str)
        if field_type == "boolean":
            return type(item) is bool
        if field_type == "int64":
            return type(item) is int and -(2**63) <= item <= 2**63 - 1
        if field_type == "uint32":
            return type(item) is int and 0 <= item <= 2**32 - 1
        if field_type == "uint64":
            return type(item) is int and 0 <= item <= 2**64 - 1
        if field_type in {"double", "metric_number"}:
            return type(item) in {int, float} and (type(item) is int or math.isfinite(item))
        if field_type in {"object", "canonical_json", "field_class_map"}:
            return isinstance(item, Mapping)
        if field_type == "array":
            return isinstance(item, tuple)
        return False

    if const_present and not value_matches_type(const):
        raise RegistryError(f"{path}.const: value does not match structural field type")
    if any(not value_matches_type(item) for item in enum):
        raise RegistryError(f"{path}.enum: value does not match structural field type")

    def optional_ref(key: str) -> str | None:
        if key not in value:
            return None
        return _string(value[key], f"{path}.{key}", pattern=_ID)

    object_ref = optional_ref("object_ref")
    item_ref = optional_ref("item_ref")
    semantic_ref = optional_ref("semantic_ref")
    semantic_format = optional_ref("semantic_format")
    if semantic_format is not None:
        if semantic_format not in STRUCTURAL_SEMANTIC_FORMATS:
            raise RegistryError(f"{path}.semantic_format: unsupported value")
        if field_type != "string":
            raise RegistryError(f"{path}.semantic_format: allowed only on string fields")
    if (field_type == "object") != (object_ref is not None):
        raise RegistryError(f"{path}.object_ref: required exactly for object fields")
    if (field_type == "array") != (item_ref is not None):
        raise RegistryError(f"{path}.item_ref: required exactly for array fields")
    if field_type in {"canonical_json", "field_class_map"} and (object_ref is not None or item_ref is not None):
        raise RegistryError(f"{path}: dynamic payload fields cannot reference structural objects")
    if "field_class" not in value or value["field_class"] not in _FIELD_CLASS:
        raise RegistryError(f"{path}.field_class: required canonical field class")
    field_class = value["field_class"]
    if "sensitivity" not in value or value["sensitivity"] not in _SENSITIVITY:
        raise RegistryError(f"{path}.sensitivity: required canonical sensitivity")
    sensitivity = value["sensitivity"]
    if "normalization" not in value:
        raise RegistryError(f"{path}.normalization: required for structural fields")
    compatibility_types = {
        "uint32": ("int64",),
        "uint64": ("int64",),
        "timestamp": ("string",),
        "canonical_json": ("object",),
        "field_class_map": ("object",),
        # metric_number is a tagged family-resolved int64|double union. Its
        # structural bound is the finite double superset; family validation
        # below preserves exact int64 semantics where selected.
        "metric_number": ("double",),
    }.get(field_type, (field_type,))
    normalization = _parse_normalization(
        value["normalization"],
        f"{path}.normalization",
        normalizers,
        field_types=compatibility_types,
    )
    effective_enum = normalization.effective_constraints.get("enum")
    if enum and effective_enum != enum:
        raise RegistryError(f"{path}: field enum and normalization enum must match")
    if const_present:
        if effective_enum is not None and effective_enum != (const,):
            raise RegistryError(f"{path}: const and normalization enum must match")
        minimum = normalization.effective_constraints.get("min")
        maximum = normalization.effective_constraints.get("max")
        if (minimum is not None and const < minimum) or (maximum is not None and const > maximum):
            raise RegistryError(f"{path}: const lies outside normalization range")
    otlp_target = None
    otlp_encoding = None
    if "otlp" in value:
        otlp = value["otlp"]
        if not isinstance(otlp, dict):
            raise RegistryError(f"{path}.otlp: expected mapping")
        _exact_keys(otlp, {"target", "encoding"}, set(), f"{path}.otlp")
        otlp_target = _string(otlp["target"], f"{path}.otlp.target")
        otlp_encoding = _string(otlp["encoding"], f"{path}.otlp.encoding", pattern=_ID)
        if otlp_encoding not in {
            "direct",
            "hex",
            "uint64_string",
            "enum_number",
            "key_value_array",
            "message",
        }:
            raise RegistryError(f"{path}.otlp.encoding: unsupported value")
    return StructuralFieldIR(
        name,
        field_type,
        value["required"],
        const_present,
        const,
        enum,
        object_ref,
        item_ref,
        semantic_ref,
        semantic_format,
        field_class,
        sensitivity,
        normalization,
        otlp_target,
        otlp_encoding,
    )


def _parse_structural_object(
    value: Any,
    path: str,
    object_id: str,
    normalizers: dict[str, NormalizerIR],
) -> StructuralObjectIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(value, {"additional_properties", "fields"}, set(), path)
    if value["additional_properties"] is not False:
        raise RegistryError(f"{path}.additional_properties: must be false")
    raw_fields = value["fields"]
    if not isinstance(raw_fields, list) or not raw_fields:
        raise RegistryError(f"{path}.fields: expected nonempty sequence")
    fields = tuple(
        _parse_structural_field(item, f"{path}.fields[{index}]", normalizers) for index, item in enumerate(raw_fields)
    )
    field_ids = tuple(item.name for item in fields)
    if len(field_ids) != len(set(field_ids)):
        raise RegistryError(f"{path}.fields: duplicate structural field")
    if any(re.fullmatch(r"[a-z][a-z0-9_]*", field.name) is None for field in fields):
        raise RegistryError(f"{path}.fields: canonical structural names must be snake_case")
    return StructuralObjectIR(object_id, False, fields)


def _parse_provenance_import_rules(
    value: Any,
    path: str,
    provenance_import: StructuralObjectIR,
) -> ProvenanceImportRulesIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(value, set(PROVENANCE_IMPORT_RULE_KEYS), set(), path)
    parsed_sequences = {
        key: _string_list(value[key], f"{path}.{key}")
        for key in PROVENANCE_IMPORT_RULE_KEYS
        if key not in {"exact_validation_owner"}
    }
    owner = _string(value["exact_validation_owner"], f"{path}.exact_validation_owner")
    observed: dict[str, str | tuple[str, ...]] = dict(parsed_sequences)
    observed["exact_validation_owner"] = owner
    if observed != EXPECTED_PROVENANCE_IMPORT_RULES:
        raise RegistryError(f"{path}: differs from the canonical provenance import rules")

    fields = {field.name: field for field in provenance_import.fields}
    upstream_record_id_pattern = (
        "^([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|[a-z0-9][a-z0-9_.-]{0,127})$"
    )
    expected_shapes: tuple[
        tuple[
            str,
            str,
            bool,
            bool,
            FrozenJSON | None,
            tuple[FrozenJSON, ...],
            str,
            str,
            str,
            Mapping[str, FrozenJSON],
        ],
        ...,
    ] = (
        (
            "protocol",
            "string",
            True,
            True,
            "otlp",
            (),
            "metadata",
            "safe",
            "enum-v1",
            {"enum": ("otlp",), "max_utf8_bytes": 256},
        ),
        (
            "binding_id",
            "string",
            True,
            False,
            None,
            (),
            "identifier",
            "internal",
            "bounded-v1",
            {"max_items": 256, "max_item_utf8_bytes": 4096, "max_utf8_bytes": 512},
        ),
        (
            "mode",
            "string",
            True,
            False,
            None,
            ("import", "derive", "import_and_derive"),
            "metadata",
            "safe",
            "enum-v1",
            {"enum": ("import", "derive", "import_and_derive"), "max_utf8_bytes": 256},
        ),
        (
            "derivation",
            "string",
            False,
            False,
            None,
            ("field_value", "elapsed_time", "cumulative_delta", "arithmetic_mean"),
            "metadata",
            "safe",
            "enum-v1",
            {"enum": ("field_value", "elapsed_time", "cumulative_delta", "arithmetic_mean"), "max_utf8_bytes": 256},
        ),
        (
            "source_aggregate_count",
            "uint64",
            False,
            False,
            None,
            (),
            "metadata",
            "safe",
            "numeric-range-v1",
            {"min": 1, "max": 18446744073709551615},
        ),
        (
            "authenticated_source",
            "string",
            True,
            False,
            None,
            (),
            "identifier",
            "internal",
            "bounded-v1",
            {"max_items": 256, "max_item_utf8_bytes": 4096, "max_utf8_bytes": 512},
        ),
        (
            "upstream_instance_id",
            "string",
            False,
            False,
            None,
            (),
            "identifier",
            "internal",
            "bounded-v1",
            {"max_items": 256, "max_item_utf8_bytes": 4096, "max_utf8_bytes": 512},
        ),
        (
            "upstream_record_id",
            "string",
            False,
            False,
            None,
            (),
            "identifier",
            "internal",
            "identifier-v1",
            {
                "max_utf8_bytes": 128,
                "pattern": upstream_record_id_pattern,
            },
        ),
        (
            "upstream_service_name",
            "string",
            False,
            False,
            None,
            (),
            "metadata",
            "internal",
            "bounded-v1",
            {"max_items": 256, "max_item_utf8_bytes": 4096, "max_utf8_bytes": 512},
        ),
        (
            "upstream_redaction_profile",
            "string",
            False,
            False,
            None,
            (),
            "metadata",
            "internal",
            "identifier-v1",
            {"max_utf8_bytes": 128, "pattern": "^[a-z0-9][a-z0-9_.-]{0,127}$"},
        ),
        (
            "ingress_hop_count",
            "uint32",
            True,
            False,
            None,
            (),
            "metadata",
            "safe",
            "numeric-range-v1",
            {"min": 0, "max": 4},
        ),
        (
            "last_hop_instance_id",
            "string",
            False,
            False,
            None,
            (),
            "identifier",
            "internal",
            "bounded-v1",
            {"max_items": 256, "max_item_utf8_bytes": 4096, "max_utf8_bytes": 512},
        ),
        (
            "last_hop_destination",
            "string",
            False,
            False,
            None,
            (),
            "identifier",
            "internal",
            "bounded-v1",
            {"max_items": 256, "max_item_utf8_bytes": 4096, "max_utf8_bytes": 512},
        ),
    )
    if tuple(fields) != tuple(item[0] for item in expected_shapes):
        raise RegistryError(f"{path}: provenance import field inventory mismatch")
    for expected in expected_shapes:
        name, field_type, required, const_present, const, enum, field_class, sensitivity, normalizer, constraints = (
            expected
        )
        field = fields[name]
        if (
            field.field_type,
            field.required,
            field.const_present,
            field.const,
            field.enum,
            field.field_class,
            field.sensitivity,
            field.normalization.id if field.normalization is not None else None,
            dict(field.normalization.effective_constraints) if field.normalization is not None else None,
        ) != (
            field_type,
            required,
            const_present,
            const,
            enum,
            field_class,
            sensitivity,
            normalizer,
            dict(constraints),
        ):
            raise RegistryError(f"{path}: provenance import field {name} differs from the canonical contract")
        if any(
            item is not None
            for item in (field.object_ref, field.item_ref, field.semantic_ref, field.semantic_format, field.otlp_target)
        ):
            raise RegistryError(f"{path}: provenance import field {name} has an unsupported external binding")
    if not set(parsed_sequences["nonempty_string_fields"]) <= fields.keys():
        raise RegistryError(f"{path}.nonempty_string_fields: references an unknown field")
    return ProvenanceImportRulesIR(
        parsed_sequences["nonempty_string_fields"],
        parsed_sequences["derivation_required_modes"],
        parsed_sequences["derivation_forbidden_modes"],
        parsed_sequences["source_aggregate_count_required_derivations"],
        parsed_sequences["source_aggregate_count_forbidden_derivations"],
        parsed_sequences["source_aggregate_count_forbidden_modes"],
        owner,
        parsed_sequences["json_schema_runtime_only"],
    )


def _parse_otlp_representation(value: Any, path: str) -> CanonicalOTLPRepresentationIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(
        value,
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
        },
        set(),
        path,
    )
    representation_id = _string(value["id"], f"{path}.id", pattern=_ID)
    if representation_id != EXPECTED_OTLP_REPRESENTATION_ID:
        raise RegistryError(f"{path}.id: unexpected representation")
    expected_scalars = {
        "json_mapping": "opentelemetry_proto_json_v1",
        "attribute_encoding": "key_value_array",
        "any_value_encoding": "typed_union",
        "timestamp_encoding": "decimal_unix_nano_string",
        "id_encoding": "lowercase_hex",
    }
    for key, expected in expected_scalars.items():
        if value[key] != expected:
            raise RegistryError(f"{path}.{key}: unexpected representation setting")
    any_value_raw = value["any_value_mapping"]
    if not isinstance(any_value_raw, list):
        raise RegistryError(f"{path}.any_value_mapping: expected sequence")
    any_value_mapping: list[tuple[str, str]] = []
    for index, item in enumerate(any_value_raw):
        item_path = f"{path}.any_value_mapping[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(item, {"canonical_type", "otlp_arm"}, set(), item_path)
        any_value_mapping.append(
            (
                _string(item["canonical_type"], f"{item_path}.canonical_type", pattern=_ID),
                _string(item["otlp_arm"], f"{item_path}.otlp_arm"),
            )
        )
    if tuple(any_value_mapping) != OTLP_ANY_VALUE_MAPPING:
        raise RegistryError(f"{path}.any_value_mapping: differs from OTLP AnyValue v1")
    if value["null_value_policy"] != "reject":
        raise RegistryError(f"{path}.null_value_policy: OTLP v1 requires reject")
    object_contexts = value["object_contexts"]
    if not isinstance(object_contexts, dict) or object_contexts != OTLP_OBJECT_CONTEXTS:
        raise RegistryError(f"{path}.object_contexts: differs from OTLP trace object placement")
    field_context_overrides = value["field_context_overrides"]
    if not isinstance(field_context_overrides, dict) or field_context_overrides != OTLP_FIELD_CONTEXT_OVERRIDES:
        raise RegistryError(f"{path}.field_context_overrides: differs from OTLP field placement")

    def parse_mapping(
        raw: Any, mapping_path: str, expected: tuple[tuple[str, int], ...]
    ) -> tuple[tuple[str, int], ...]:
        if not isinstance(raw, list):
            raise RegistryError(f"{mapping_path}: expected sequence")
        parsed: list[tuple[str, int]] = []
        for index, item in enumerate(raw):
            item_path = f"{mapping_path}[{index}]"
            if not isinstance(item, dict):
                raise RegistryError(f"{item_path}: expected mapping")
            _exact_keys(item, {"canonical", "otlp"}, set(), item_path)
            parsed.append(
                (
                    _string(item["canonical"], f"{item_path}.canonical", pattern=_ID),
                    _integer(item["otlp"], f"{item_path}.otlp", minimum=0),
                )
            )
        if tuple(parsed) != expected:
            raise RegistryError(f"{mapping_path}: differs from OTLP v1")
        return tuple(parsed)

    span_kinds = parse_mapping(
        value["span_kind_mapping"],
        f"{path}.span_kind_mapping",
        OTLP_SPAN_KIND_MAPPING,
    )
    status_codes = parse_mapping(
        value["status_code_mapping"],
        f"{path}.status_code_mapping",
        OTLP_STATUS_CODE_MAPPING,
    )
    signals_raw = value["signals"]
    if not isinstance(signals_raw, list):
        raise RegistryError(f"{path}.signals: expected sequence")
    signals: list[OTLPSignalRepresentationIR] = []
    for index, item in enumerate(signals_raw):
        item_path = f"{path}.signals[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(item, {"signal", "mode"}, {"request_root"}, item_path)
        signal = _string(item["signal"], f"{item_path}.signal")
        mode = _string(item["mode"], f"{item_path}.mode", pattern=_ID)
        request_root = None
        if "request_root" in item:
            request_root = _string(item["request_root"], f"{item_path}.request_root")
        signals.append(OTLPSignalRepresentationIR(signal, mode, request_root))
    expected_signals = (
        ("logs", "projected_record_json_string", "resourceLogs"),
        ("traces", "direct_span", "resourceSpans"),
        ("metrics", "sdk_aggregation_required", "resourceMetrics"),
    )
    if tuple((item.signal, item.mode, item.request_root) for item in signals) != expected_signals:
        raise RegistryError(f"{path}.signals: differs from the canonical OTLP representation")
    return CanonicalOTLPRepresentationIR(
        representation_id,
        expected_scalars["json_mapping"],
        expected_scalars["attribute_encoding"],
        expected_scalars["any_value_encoding"],
        tuple(any_value_mapping),
        "reject",
        MappingProxyType(dict(object_contexts)),
        MappingProxyType(dict(field_context_overrides)),
        expected_scalars["timestamp_encoding"],
        expected_scalars["id_encoding"],
        span_kinds,
        status_codes,
        tuple(signals),
    )


def _parse_structural_contract(
    value: Any,
    path: str,
    normalizers: dict[str, NormalizerIR],
) -> StructuralContractIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(
        value,
        {
            "id",
            "version",
            "additional_properties",
            "runtime_binding",
            "limits",
            "envelope",
            "correlation",
            "provenance",
            "provenance_import",
            "trace",
            "metric",
            "canonical_to_otlp",
        },
        set(),
        path,
    )
    contract_id = _string(value["id"], f"{path}.id", pattern=_ID)
    if contract_id != EXPECTED_STRUCTURAL_CONTRACT_ID:
        raise RegistryError(f"{path}.id: unexpected contract")
    version = _integer(value["version"], f"{path}.version")
    if version != 1:
        raise RegistryError(f"{path}.version: unsupported version")
    if value["additional_properties"] is not False:
        raise RegistryError(f"{path}.additional_properties: must be false")
    runtime_binding = value["runtime_binding"]
    if not isinstance(runtime_binding, dict):
        raise RegistryError(f"{path}.runtime_binding: expected mapping")
    _exact_keys(
        runtime_binding,
        set(STRUCTURAL_RUNTIME_BINDING_KEYS),
        set(),
        f"{path}.runtime_binding",
    )
    for key in STRUCTURAL_RUNTIME_BINDING_KEYS:
        _string(runtime_binding[key], f"{path}.runtime_binding.{key}", pattern=_ID)
    runtime_binding_ir = StructuralRuntimeBindingIR(
        runtime_binding["record"],
        runtime_binding["input"],
        runtime_binding["value"],
        runtime_binding["schema_derived_constructor"],
        runtime_binding["schema_derived_log_constructor"],
    )
    limits = value["limits"]
    if not isinstance(limits, dict):
        raise RegistryError(f"{path}.limits: expected mapping")
    _exact_keys(limits, set(STRUCTURAL_LIMIT_KEYS), set(), f"{path}.limits")
    for key in STRUCTURAL_LIMIT_KEYS:
        _integer(limits[key], f"{path}.limits.{key}")
    if limits["record_encoded_bytes"] < limits["payload_encoded_bytes"]:
        raise RegistryError(f"{path}.limits: record bound must contain one payload")
    limits_ir = StructuralLimitsIR(MappingProxyType(dict(limits)))
    envelope_raw = value["envelope"]
    if not isinstance(envelope_raw, dict):
        raise RegistryError(f"{path}.envelope: expected mapping")
    _exact_keys(
        envelope_raw,
        {"additional_properties", "fields", "signal_arms"},
        set(),
        f"{path}.envelope",
    )
    envelope = _parse_structural_object(
        {
            "additional_properties": envelope_raw["additional_properties"],
            "fields": envelope_raw["fields"],
        },
        f"{path}.envelope",
        "envelope",
        normalizers,
    )
    envelope_fields = frozenset(field.name for field in envelope.fields)
    arms_raw = envelope_raw["signal_arms"]
    if not isinstance(arms_raw, list):
        raise RegistryError(f"{path}.envelope.signal_arms: expected sequence")
    arms: list[SignalArmIR] = []
    for index, item in enumerate(arms_raw):
        item_path = f"{path}.envelope.signal_arms[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(
            item,
            {
                "signal",
                "payload_field",
                "required_fields",
                "forbidden_fields",
                "required_correlation_fields",
            },
            set(),
            item_path,
        )
        signal = _string(item["signal"], f"{item_path}.signal")
        payload_field = _string(item["payload_field"], f"{item_path}.payload_field")
        required = _string_list(item["required_fields"], f"{item_path}.required_fields")
        forbidden = _string_list(item["forbidden_fields"], f"{item_path}.forbidden_fields")
        required_correlation = _string_list(
            item["required_correlation_fields"],
            f"{item_path}.required_correlation_fields",
        )
        if not ({payload_field, *required, *forbidden} <= envelope_fields):
            raise RegistryError(f"{item_path}: references an unknown envelope field")
        if set(required) & set(forbidden) or payload_field in forbidden:
            raise RegistryError(f"{item_path}: contradictory field policy")
        arms.append(SignalArmIR(signal, payload_field, required, forbidden, required_correlation))
    if tuple(item.signal for item in arms) != ("logs", "traces", "metrics"):
        raise RegistryError(f"{path}.envelope.signal_arms: expected canonical signal order")
    correlation = _parse_structural_object(value["correlation"], f"{path}.correlation", "correlation", normalizers)
    provenance = _parse_structural_object(value["provenance"], f"{path}.provenance", "provenance", normalizers)
    provenance_import_raw = value["provenance_import"]
    if not isinstance(provenance_import_raw, dict):
        raise RegistryError(f"{path}.provenance_import: expected mapping")
    _exact_keys(
        provenance_import_raw,
        {"additional_properties", "fields", "rules"},
        set(),
        f"{path}.provenance_import",
    )
    provenance_import = _parse_structural_object(
        {
            "additional_properties": provenance_import_raw["additional_properties"],
            "fields": provenance_import_raw["fields"],
        },
        f"{path}.provenance_import",
        "provenance_import",
        normalizers,
    )
    provenance_import_rules = _parse_provenance_import_rules(
        provenance_import_raw["rules"],
        f"{path}.provenance_import.rules",
        provenance_import,
    )
    trace = value["trace"]
    if not isinstance(trace, dict):
        raise RegistryError(f"{path}.trace: expected mapping")
    _exact_keys(
        trace,
        {"derivations", "body", "resource", "scope", "status", "events", "links"},
        set(),
        f"{path}.trace",
    )
    derivations_raw = trace["derivations"]
    if not isinstance(derivations_raw, list) or not derivations_raw:
        raise RegistryError(f"{path}.trace.derivations: expected nonempty sequence")
    derivations: list[TraceDerivationIR] = []
    for index, item in enumerate(derivations_raw):
        item_path = f"{path}.trace.derivations[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(
            item,
            {"id", "source", "equality", "presence"},
            {"target_attribute", "target_field"},
            item_path,
        )
        has_target_attribute = "target_attribute" in item
        has_target_field = "target_field" in item
        if has_target_attribute == has_target_field:
            raise RegistryError(f"{item_path}: expected exactly one of target_attribute or target_field")
        derivations.append(
            TraceDerivationIR(
                _string(item["id"], f"{item_path}.id", pattern=_ID),
                (
                    _string(item["target_attribute"], f"{item_path}.target_attribute", pattern=_ID)
                    if has_target_attribute
                    else None
                ),
                (_string(item["target_field"], f"{item_path}.target_field", pattern=_ID) if has_target_field else None),
                _string(item["source"], f"{item_path}.source", pattern=_ID),
                _string(item["equality"], f"{item_path}.equality", pattern=_ID),
                _string(item["presence"], f"{item_path}.presence", pattern=_ID),
            )
        )
    observed_derivations = {
        (
            item.id,
            "target_attribute" if item.target_attribute is not None else "target_field",
            item.target_attribute if item.target_attribute is not None else item.target_field,
            item.source,
            item.equality,
            item.presence,
        )
        for item in derivations
    }
    if len(observed_derivations) != len(derivations):
        raise RegistryError(f"{path}.trace.derivations: duplicate binding")
    if observed_derivations != set(TRACE_DERIVATION_BINDINGS):
        raise RegistryError(f"{path}.trace.derivations: binding inventory mismatch")
    derivations.sort(key=lambda item: item.id)
    trace_body_raw = trace["body"]
    if not isinstance(trace_body_raw, dict):
        raise RegistryError(f"{path}.trace.body: expected mapping")
    _exact_keys(trace_body_raw, {"additional_properties", "fields", "relations"}, set(), f"{path}.trace.body")
    trace_body = _parse_structural_object(
        {
            "additional_properties": trace_body_raw["additional_properties"],
            "fields": trace_body_raw["fields"],
        },
        f"{path}.trace.body",
        "trace_body",
        normalizers,
    )
    relations_raw = trace_body_raw["relations"]
    if not isinstance(relations_raw, list) or not relations_raw:
        raise RegistryError(f"{path}.trace.body.relations: expected nonempty sequence")
    relations: list[StructuralRelationIR] = []
    relation_ids: set[str] = set()
    trace_body_fields = {field.name: field for field in trace_body.fields}
    for index, relation in enumerate(relations_raw):
        relation_path = f"{path}.trace.body.relations[{index}]"
        if not isinstance(relation, dict):
            raise RegistryError(f"{relation_path}: expected mapping")
        _exact_keys(relation, {"id", "kind", "left", "right"}, set(), relation_path)
        relation_id = _string(relation["id"], f"{relation_path}.id", pattern=_ID)
        if relation_id in relation_ids:
            raise RegistryError(f"{path}.trace.body.relations: duplicate relation ID")
        kind = _string(relation["kind"], f"{relation_path}.kind", pattern=_ID)
        if kind != "less_than_or_equal":
            raise RegistryError(f"{relation_path}.kind: unsupported structural relation")
        left = _string(relation["left"], f"{relation_path}.left")
        right = _string(relation["right"], f"{relation_path}.right")
        for side, field_name in (("left", left), ("right", right)):
            field = trace_body_fields.get(field_name)
            if field is None or field.field_type not in {"int64", "uint32", "uint64", "double", "metric_number"}:
                raise RegistryError(f"{relation_path}.{side}: expected numeric trace-body field")
        relations.append(StructuralRelationIR(relation_id, kind, left, right))
        relation_ids.add(relation_id)
    if not any(
        relation.kind == "less_than_or_equal"
        and relation.left == "start_time_unix_nano"
        and relation.right == "end_time_unix_nano"
        for relation in relations
    ):
        raise RegistryError(f"{path}.trace.body.relations: missing trace time-order relation")
    resource = _parse_structural_object(trace["resource"], f"{path}.trace.resource", "trace_resource", normalizers)
    scope = _parse_structural_object(trace["scope"], f"{path}.trace.scope", "trace_scope", normalizers)
    status = _parse_structural_object(trace["status"], f"{path}.trace.status", "trace_status", normalizers)
    event = _parse_structural_object(trace["events"], f"{path}.trace.events", "trace_event", normalizers)
    link = _parse_structural_object(trace["links"], f"{path}.trace.links", "trace_link", normalizers)
    metric = value["metric"]
    if not isinstance(metric, dict):
        raise RegistryError(f"{path}.metric: expected mapping")
    _exact_keys(metric, {"instrument_data"}, set(), f"{path}.metric")
    instrument = _parse_structural_object(
        metric["instrument_data"],
        f"{path}.metric.instrument_data",
        "metric_instrument_data",
        normalizers,
    )
    structural_objects = {
        "correlation": correlation,
        "provenance": provenance,
        "provenance_import": provenance_import,
        "trace_body": trace_body,
        "trace_resource": resource,
        "trace_scope": scope,
        "trace_status": status,
        "trace_event": event,
        "trace_link": link,
        "metric_instrument_data": instrument,
    }
    for object_ir in (envelope, *structural_objects.values()):
        for field in object_ir.fields:
            if field.object_ref is not None and field.object_ref not in structural_objects:
                raise RegistryError(f"{path}.{object_ir.id}.{field.name}.object_ref: unknown structural object")
            if field.item_ref is not None and field.item_ref not in structural_objects:
                raise RegistryError(f"{path}.{object_ir.id}.{field.name}.item_ref: unknown structural object")
    for object_ir in (envelope, *structural_objects.values()):
        expected_mappings = OTLP_FIELD_MAPPINGS[object_ir.id]
        observed_targets: set[str] = set()
        for field in object_ir.fields:
            expected_mapping = expected_mappings.get(field.name)
            observed_mapping = None if field.otlp_target is None else (field.otlp_target, field.otlp_encoding)
            if observed_mapping != expected_mapping:
                raise RegistryError(f"{path}.{object_ir.id}.{field.name}.otlp: typed OTLP mapping mismatch")
            if field.otlp_target is not None:
                if field.otlp_target in observed_targets:
                    raise RegistryError(f"{path}.{object_ir.id}: duplicate OTLP target")
                observed_targets.add(field.otlp_target)
    return StructuralContractIR(
        contract_id,
        version,
        False,
        runtime_binding_ir,
        limits_ir,
        envelope,
        correlation,
        provenance,
        provenance_import,
        provenance_import_rules,
        tuple(arms),
        tuple(derivations),
        trace_body,
        tuple(relations),
        resource,
        scope,
        status,
        event,
        link,
        instrument,
        _parse_otlp_representation(value["canonical_to_otlp"], f"{path}.canonical_to_otlp"),
    )


def _parse_attribute_definition(
    value: Any,
    path: str,
    normalizers: dict[str, NormalizerIR],
) -> AttributeIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    required = {
        "id",
        "type",
        "brief",
        "examples",
        "stability",
        "owner",
        "field_class",
        "sensitivity",
        "cardinality",
        "normalization",
        "introduced_in",
    }
    optional = {
        "deprecated_in",
        "removed_in",
        "alias_of",
        "projection_only",
        "legacy_bindings",
    }
    _exact_keys(value, required, optional, path)
    attribute_id = _string(value["id"], f"{path}.id", pattern=_ID)
    if value["type"] not in _FIELD_TYPE:
        raise RegistryError(f"{path}.type: unsupported field type")
    field_type = value["type"]
    brief = _string(value["brief"], f"{path}.brief")
    if not isinstance(value["examples"], list):
        raise RegistryError(f"{path}.examples: expected sequence")
    for index, example in enumerate(value["examples"]):
        _validate_json_compatible(example, f"{path}.examples[{index}]")
    examples = tuple(_freeze_json(example) for example in value["examples"])
    for key, allowed in (
        ("stability", _STABILITY),
        ("owner", _OWNER),
        ("field_class", _FIELD_CLASS),
        ("sensitivity", _SENSITIVITY),
        ("cardinality", _CARDINALITY),
    ):
        if value[key] not in allowed:
            raise RegistryError(f"{path}.{key}: unsupported value")
    normalization = _parse_normalization(
        value["normalization"],
        f"{path}.normalization",
        normalizers,
        field_types=(field_type,),
    )
    for index, example in enumerate(value["examples"]):
        if not _attribute_type_accepts(example, field_type):
            raise RegistryError(f"{path}.examples[{index}]: value does not match declared attribute type")
        if not _normalization_accepts(example, normalization):
            raise RegistryError(f"{path}.examples[{index}]: value violates declared normalization")
    introduced_in = _string(value["introduced_in"], f"{path}.introduced_in", pattern=_ID)
    deprecated_in = None
    removed_in = None
    if "deprecated_in" in value:
        deprecated_in = _string(value["deprecated_in"], f"{path}.deprecated_in", pattern=_ID)
    if "removed_in" in value:
        removed_in = _string(value["removed_in"], f"{path}.removed_in", pattern=_ID)
    alias = None
    if "alias_of" in value:
        alias = _string(value["alias_of"], f"{path}.alias_of", pattern=_ID)
    projection_only = value.get("projection_only", False)
    if type(projection_only) is not bool:
        raise RegistryError(f"{path}.projection_only: expected boolean")
    legacy_bindings = (
        _parse_legacy_bindings(value["legacy_bindings"], f"{path}.legacy_bindings")
        if "legacy_bindings" in value
        else None
    )
    if projection_only and "legacy_bindings" not in value:
        raise RegistryError(f"{path}.legacy_bindings: required for projection-only aliases")
    return AttributeIR(
        attribute_id,
        field_type,
        brief,
        examples,
        alias,
        value["owner"],
        value["stability"],
        deprecated_in,
        removed_in,
        projection_only,
        value["field_class"],
        value["sensitivity"],
        value["cardinality"],
        normalization,
        introduced_in,
        legacy_bindings,
    )


def _parse_attribute_extension(
    value: Any,
    path: str,
    normalizers: dict[str, NormalizerIR],
) -> AttributeExtensionIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(
        value,
        {"ref", "field_class", "sensitivity", "cardinality", "normalization"},
        set(),
        path,
    )
    ref = _string(value["ref"], f"{path}.ref", pattern=_ID)
    for key, allowed in (
        ("field_class", _FIELD_CLASS),
        ("sensitivity", _SENSITIVITY),
        ("cardinality", _CARDINALITY),
    ):
        if value[key] not in allowed:
            raise RegistryError(f"{path}.{key}: unsupported value")
    normalization = _parse_normalization(
        value["normalization"],
        f"{path}.normalization",
        normalizers,
    )
    return AttributeExtensionIR(
        ref,
        value["field_class"],
        value["sensitivity"],
        value["cardinality"],
        normalization,
    )


def _parse_attribute_uses(
    value: Any,
    path: str,
    role: str,
) -> tuple[AttributeUseIR, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise RegistryError(f"{path}: expected sequence")
    result: list[AttributeUseIR] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(item, {"ref", "requirement_level"}, {"conditional", "constraints"}, item_path)
        reference = _string(item["ref"], f"{item_path}.ref", pattern=_ID)
        requirement_level = item["requirement_level"]
        if requirement_level not in {"required", "recommended", "optional", "conditional"}:
            raise RegistryError(f"{item_path}.requirement_level: unsupported value")
        if requirement_level == "conditional":
            if "conditional" not in item:
                raise RegistryError(f"{item_path}.conditional: required for conditional fields")
        elif "conditional" in item and requirement_level != "optional":
            raise RegistryError(f"{item_path}.conditional: allowed only for conditional or optional fields")
        conditional = None
        if "conditional" in item:
            conditional = _string(item["conditional"], f"{item_path}.conditional")
        constraints: dict[str, Any] = {}
        if "constraints" in item:
            constraints = _validate_constraint_map(
                item["constraints"],
                f"{item_path}.constraints",
            )
        result.append(
            AttributeUseIR(
                reference,
                role,
                requirement_level,
                conditional,
                _freeze_mapping(constraints),
            )
        )
    if len(result) != len({item.ref for item in result}):
        raise RegistryError(f"{path}: duplicate attribute reference")
    return tuple(result)


def _parse_legacy_bindings(value: Any, path: str) -> tuple[LegacyBindingIR, ...]:
    if not isinstance(value, list):
        raise RegistryError(f"{path}: expected sequence")
    result: list[LegacyBindingIR] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(item, {"source", "disposition"}, {"details"}, item_path)
        source = _string(item["source"], f"{item_path}.source")
        disposition = _string(item["disposition"], f"{item_path}.disposition", pattern=_ID)
        details_present = "details" in item
        details = None
        if "details" in item:
            _validate_json_compatible(item["details"], f"{item_path}.details")
            details = _freeze_json(item["details"])
        result.append(LegacyBindingIR(source, disposition, details_present, details))
    return tuple(result)


def _parse_metric_projections(value: Any, path: str) -> tuple[MetricProjectionIR, ...]:
    if not isinstance(value, list):
        raise RegistryError(f"{path}: expected sequence")
    projections: list[MetricProjectionIR] = []
    seen_profiles: set[str] = set()
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(item, {"profile", "mappings"}, set(), item_path)
        profile = _string(item["profile"], f"{item_path}.profile", pattern=_ID)
        if profile in seen_profiles:
            raise RegistryError(f"{path}: duplicate profile")
        if profile != "local-observability-v1":
            raise RegistryError(f"{item_path}.profile: unknown metric compatibility profile")
        mappings = item["mappings"]
        if not isinstance(mappings, list) or not mappings:
            raise RegistryError(f"{item_path}.mappings: expected nonempty sequence")
        parsed: list[tuple[str, str]] = []
        seen_refs: set[str] = set()
        seen_labels: set[str] = set()
        for mapping_index, mapping in enumerate(mappings):
            mapping_path = f"{item_path}.mappings[{mapping_index}]"
            if not isinstance(mapping, dict):
                raise RegistryError(f"{mapping_path}: expected mapping")
            _exact_keys(mapping, {"ref", "label"}, set(), mapping_path)
            reference = _string(mapping["ref"], f"{mapping_path}.ref", pattern=_ID)
            label = _string(mapping["label"], f"{mapping_path}.label", pattern=_ID)
            if reference in seen_refs:
                raise RegistryError(f"{item_path}.mappings: duplicate ref")
            if label in seen_labels:
                raise RegistryError(f"{item_path}.mappings: duplicate projected label")
            if reference == label:
                raise RegistryError(f"{mapping_path}: identity projection must be omitted")
            seen_refs.add(reference)
            seen_labels.add(label)
            parsed.append((reference, label))
        seen_profiles.add(profile)
        projections.append(MetricProjectionIR(profile, tuple(parsed)))
    return tuple(projections)


def _parse_resource_dynamic_members(value: Any, path: str) -> ResourceDynamicMembersIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    fields = {
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
    _exact_keys(value, fields, set(), path)
    parsed = ResourceDynamicMembersIR(
        _string(value["ordering"], f"{path}.ordering"),
        _string(value["field_class"], f"{path}.field_class"),
        _string(value["sensitivity"], f"{path}.sensitivity"),
        _string(value["cardinality"], f"{path}.cardinality"),
        _string(value["stability_scope"], f"{path}.stability_scope"),
        _string(value["value_utf8_policy"], f"{path}.value_utf8_policy"),
        _string(value["value_blank_policy"], f"{path}.value_blank_policy"),
        _string(value["value_control_character_policy"], f"{path}.value_control_character_policy"),
        _string(value["prometheus_key_normalization"], f"{path}.prometheus_key_normalization"),
        _string(
            value["prometheus_normalized_collision_policy"],
            f"{path}.prometheus_normalized_collision_policy",
        ),
        _string(value["key_pattern"], f"{path}.key_pattern"),
        _integer(value["max_items"], f"{path}.max_items", minimum=1),
        _integer(value["max_key_ascii_bytes"], f"{path}.max_key_ascii_bytes", minimum=1),
        _integer(value["min_value_utf8_bytes"], f"{path}.min_value_utf8_bytes", minimum=1),
        _integer(value["max_value_utf8_bytes"], f"{path}.max_value_utf8_bytes", minimum=1),
        _integer(value["max_aggregate_utf8_bytes"], f"{path}.max_aggregate_utf8_bytes", minimum=1),
        _string(value["duplicate_key_policy"], f"{path}.duplicate_key_policy"),
        _string(value["fixed_key_collision_policy"], f"{path}.fixed_key_collision_policy"),
        _string_list(value["forbidden_key_segments"], f"{path}.forbidden_key_segments", allow_empty=False),
        _string_list(value["reserved_keys"], f"{path}.reserved_keys", allow_empty=False),
        _string_list(value["forbidden_value_classes"], f"{path}.forbidden_value_classes", allow_empty=False),
    )
    expected = ResourceDynamicMembersIR(
        "bytewise_key_ascending",
        "metadata",
        "internal",
        "bounded",
        "process",
        "require_valid",
        "reject_trimmed_empty",
        "reject",
        "dot_dash_to_underscore",
        "reject",
        r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$",
        64,
        128,
        1,
        1024,
        16384,
        "reject",
        "reject",
        (
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
        (
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
        ("filesystem_path", "credential_material"),
    )
    if parsed != expected:
        raise RegistryError(f"{path}: custom resource member contract differs from the canonical v8 contract")
    return parsed


def _parse_resource_compatibility_aliases(
    value: Any,
    path: str,
) -> tuple[ResourceCompatibilityAliasIR, ...]:
    if not isinstance(value, list):
        raise RegistryError(f"{path}: expected sequence")
    result: list[ResourceCompatibilityAliasIR] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(item, {"alias", "canonical"}, set(), item_path)
        result.append(
            ResourceCompatibilityAliasIR(
                _string(item["alias"], f"{item_path}.alias", pattern=_ID),
                _string(item["canonical"], f"{item_path}.canonical", pattern=_ID),
            )
        )
    expected = (
        ResourceCompatibilityAliasIR("deployment.environment", "deployment.environment.name"),
        ResourceCompatibilityAliasIR("deployment.mode", "defenseclaw.deployment.mode"),
        ResourceCompatibilityAliasIR(
            "defenseclaw.device.id",
            "defenseclaw.device.public_key_fingerprint",
        ),
    )
    parsed = tuple(result)
    if parsed != expected:
        raise RegistryError(f"{path}: compatibility aliases differ from the canonical v8 mapping")
    return parsed


def _parse_group(value: Any, path: str, mandatory_rule_ids: frozenset[str]) -> GroupIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(
        value,
        {"id", "type", "brief", "stability"},
        {
            "extends",
            "attributes",
            "body_fields",
            "span",
            "log",
            "metric",
            "x-defenseclaw",
            "introduced_in",
            "deprecated_in",
            "removed_in",
        },
        path,
    )
    group_id = _string(value["id"], f"{path}.id", pattern=_ID)
    group_type = _string(value["type"], f"{path}.type")
    if group_type not in _GROUP_TYPE:
        raise RegistryError(f"{path}.type: unsupported group type")
    brief = _string(value["brief"], f"{path}.brief")
    stability = value["stability"]
    if stability not in _STABILITY:
        raise RegistryError(f"{path}.stability: unsupported stability")
    extends = _string_list(value.get("extends", []), f"{path}.extends")
    attribute_uses = _parse_attribute_uses(
        value.get("attributes"),
        f"{path}.attributes",
        "attributes",
    )
    attribute_uses += _parse_attribute_uses(
        value.get("body_fields"),
        f"{path}.body_fields",
        "body_fields",
    )
    attribute_refs = tuple(item.ref for item in attribute_uses)
    span_name_pattern: str | None = None
    span_name_parts: tuple[SpanNamePartIR, ...] | None = None
    span_kinds: tuple[str, ...] | None = None
    span_status_rule: str | None = None
    if "span" in value:
        if group_type != "span" or not isinstance(value["span"], dict):
            raise RegistryError(f"{path}.span: allowed only on span groups")
        _exact_keys(value["span"], {"name_pattern", "kinds", "status_rule"}, set(), f"{path}.span")
        span_name_pattern = _string(
            value["span"]["name_pattern"],
            f"{path}.span.name_pattern",
        )
        span_name_parts = _compile_span_name_parts(span_name_pattern)
        if span_name_parts is None:
            raise RegistryError(f"{path}.span.name_pattern: invalid or transformed pattern")
        span_kinds = _string_list(
            value["span"]["kinds"],
            f"{path}.span.kinds",
            allow_empty=False,
        )
        if not set(span_kinds).issubset(EXPECTED_SPAN_KINDS):
            raise RegistryError(f"{path}.span.kinds: unsupported OTel span kind")
        span_status_rule = _string(value["span"]["status_rule"], f"{path}.span.status_rule")
    elif group_type == "span":
        raise RegistryError(f"{path}.span: required for span groups")
    event_name: str | None = None
    if "log" in value:
        if group_type != "log" or not isinstance(value["log"], dict):
            raise RegistryError(f"{path}.log: allowed only on log groups")
        _exact_keys(value["log"], {"event_name"}, set(), f"{path}.log")
        event_name = _string(value["log"]["event_name"], f"{path}.log.event_name", pattern=_ID)
    elif group_type == "log":
        raise RegistryError(f"{path}.log: required for log groups")
    instrument_name: str | None = None
    instrument_type: str | None = None
    metric_value_type: str | None = None
    metric_unit: str | None = None
    metric_description: str | None = None
    metric_temporality: str | None = None
    metric_boundaries: tuple[int | float, ...] | None = None
    empty_labels_reason: str | None = None
    metric_projections: tuple[MetricProjectionIR, ...] = ()
    if "metric" in value:
        if group_type != "metric" or not isinstance(value["metric"], dict):
            raise RegistryError(f"{path}.metric: allowed only on metric groups")
        _exact_keys(
            value["metric"],
            {"instrument_name", "instrument_type", "value_type", "unit", "description", "temporality"},
            {"boundaries", "empty_labels_reason", "label_projections"},
            f"{path}.metric",
        )
        for key in ("instrument_name", "instrument_type", "value_type", "unit", "description", "temporality"):
            _string(value["metric"][key], f"{path}.metric.{key}")
        instrument_name = value["metric"]["instrument_name"]
        instrument_type = value["metric"]["instrument_type"]
        metric_value_type = value["metric"]["value_type"]
        metric_unit = value["metric"]["unit"]
        metric_description = value["metric"]["description"]
        metric_temporality = value["metric"]["temporality"]
        if instrument_type not in _METRIC_INSTRUMENT_TYPES:
            raise RegistryError(f"{path}.metric.instrument_type: unsupported value")
        if metric_value_type not in _METRIC_VALUE_TYPES:
            raise RegistryError(f"{path}.metric.value_type: unsupported value")
        if metric_temporality not in _METRIC_TEMPORALITIES:
            raise RegistryError(f"{path}.metric.temporality: unsupported value")
        if "empty_labels_reason" in value["metric"]:
            empty_labels_reason = _string(
                value["metric"]["empty_labels_reason"],
                f"{path}.metric.empty_labels_reason",
            )
        if "label_projections" in value["metric"]:
            metric_projections = _parse_metric_projections(
                value["metric"]["label_projections"],
                f"{path}.metric.label_projections",
            )
        if "boundaries" in value["metric"]:
            boundaries = value["metric"]["boundaries"]
            if not isinstance(boundaries, list):
                raise RegistryError(f"{path}.metric.boundaries: expected sequence")
            if instrument_type != "histogram":
                raise RegistryError(f"{path}.metric.boundaries: allowed only for histograms")
            parsed_boundaries: list[int | float] = []
            for boundary_index, boundary in enumerate(boundaries):
                boundary_path = f"{path}.metric.boundaries[{boundary_index}]"
                if type(boundary) not in {int, float} or (type(boundary) is float and not math.isfinite(boundary)):
                    raise RegistryError(f"{boundary_path}: expected finite number")
                if parsed_boundaries and boundary <= parsed_boundaries[-1]:
                    raise RegistryError(f"{path}.metric.boundaries: values must be strictly ascending")
                parsed_boundaries.append(boundary)
            metric_boundaries = tuple(parsed_boundaries)
    elif group_type == "metric":
        raise RegistryError(f"{path}.metric: required for metric groups")
    event_refs: tuple[str, ...] | None = None
    bucket: str | None = None
    family_schema_version: int | None = None
    outcome_requirement: str | None = None
    allowed_outcomes: tuple[str, ...] | None = None
    link_relations: tuple[str, ...] | None = None
    mandatory_floor: tuple[str, ...] | None = None
    route_selector: bool | None = None
    compatibility_profiles: tuple[str, ...] | None = None
    resource_dynamic_members: ResourceDynamicMembersIR | None = None
    resource_compatibility_aliases: tuple[ResourceCompatibilityAliasIR, ...] | None = None
    legacy_bindings: tuple[LegacyBindingIR, ...] | None = None
    if "x-defenseclaw" in value:
        extension = value["x-defenseclaw"]
        if not isinstance(extension, dict):
            raise RegistryError(f"{path}.x-defenseclaw: expected mapping")
        _exact_keys(
            extension,
            set(),
            {
                "bucket",
                "family_schema_version",
                "outcome_requirement",
                "allowed_outcomes",
                "events",
                "link_relations",
                "mandatory_floor",
                "route_selector",
                "compatibility_profiles",
                "custom_resource_attributes",
                "compatibility_aliases",
                "legacy_bindings",
            },
            f"{path}.x-defenseclaw",
        )
        if "custom_resource_attributes" in extension:
            if group_type != "resource" or group_id != "resource.core":
                raise RegistryError(f"{path}.x-defenseclaw.custom_resource_attributes: allowed only on resource.core")
            resource_dynamic_members = _parse_resource_dynamic_members(
                extension["custom_resource_attributes"],
                f"{path}.x-defenseclaw.custom_resource_attributes",
            )
        if "compatibility_aliases" in extension:
            if group_type != "resource" or group_id != "resource.core":
                raise RegistryError(f"{path}.x-defenseclaw.compatibility_aliases: allowed only on resource.core")
            resource_compatibility_aliases = _parse_resource_compatibility_aliases(
                extension["compatibility_aliases"],
                f"{path}.x-defenseclaw.compatibility_aliases",
            )
        if "bucket" in extension:
            bucket = _string(extension["bucket"], f"{path}.x-defenseclaw.bucket", pattern=_ID)
            if bucket not in EXPECTED_BUCKETS:
                raise RegistryError(f"{path}.x-defenseclaw.bucket: unknown catalog-v1 bucket")
        if "family_schema_version" in extension:
            family_schema_version = _integer(
                extension["family_schema_version"],
                f"{path}.x-defenseclaw.family_schema_version",
                maximum=2**32 - 1,
            )
        if "outcome_requirement" in extension:
            outcome_requirement = _string(
                extension["outcome_requirement"],
                f"{path}.x-defenseclaw.outcome_requirement",
            )
            if outcome_requirement not in {"required", "optional", "forbidden"}:
                raise RegistryError(f"{path}.x-defenseclaw.outcome_requirement: unsupported value")
        for key in ("allowed_outcomes", "events", "link_relations", "compatibility_profiles"):
            if key in extension:
                values = _string_list(extension[key], f"{path}.x-defenseclaw.{key}")
                if key == "allowed_outcomes":
                    allowed_outcomes = values
                elif key == "events":
                    event_refs = values
                elif key == "link_relations":
                    if not set(values).issubset(EXPECTED_LINK_RELATIONS):
                        raise RegistryError(f"{path}.x-defenseclaw.link_relations: unknown relation")
                    link_relations = values
                else:
                    if not set(values).issubset(EXPECTED_COMPATIBILITY_PROFILES):
                        raise RegistryError(f"{path}.x-defenseclaw.compatibility_profiles: unknown profile")
                    compatibility_profiles = values
        if "mandatory_floor" in extension:
            mandatory_floor = _string_list(
                extension["mandatory_floor"],
                f"{path}.x-defenseclaw.mandatory_floor",
            )
            if not set(mandatory_floor).issubset(mandatory_rule_ids):
                raise RegistryError(f"{path}.x-defenseclaw.mandatory_floor: unknown rule")
            if group_type != "log":
                raise RegistryError(f"{path}.x-defenseclaw.mandatory_floor: allowed only for log families")
        if "route_selector" in extension and type(extension["route_selector"]) is not bool:
            raise RegistryError(f"{path}.x-defenseclaw.route_selector: expected boolean")
        if "route_selector" in extension:
            route_selector = extension["route_selector"]
        if "legacy_bindings" in extension:
            legacy_bindings = _parse_legacy_bindings(
                extension["legacy_bindings"],
                f"{path}.x-defenseclaw.legacy_bindings",
            )
    if group_type in _SIGNAL_BY_GROUP_TYPE:
        if bucket is None:
            raise RegistryError(f"{path}.x-defenseclaw.bucket: required for signal families")
        if not isinstance(value.get("x-defenseclaw"), dict) or "family_schema_version" not in value["x-defenseclaw"]:
            raise RegistryError(f"{path}.x-defenseclaw.family_schema_version: required for signal families")
    if group_id == "resource.core":
        production_fixed = {
            "service.name",
            "service.version",
            "service.namespace",
            "service.instance.id",
            "deployment.environment.name",
            "host.name",
            "host.arch",
            "os.type",
            "tenant.id",
            "workspace.id",
            "defenseclaw.deployment.mode",
            "defenseclaw.claw.mode",
            "defenseclaw.instance.id",
            "defenseclaw.device.public_key_fingerprint",
        }
        if (resource_dynamic_members is None) != (resource_compatibility_aliases is None):
            raise RegistryError(f"{path}.x-defenseclaw: resource custom members and aliases must be declared together")
        if set(attribute_refs) == production_fixed and resource_dynamic_members is None:
            raise RegistryError(f"{path}.x-defenseclaw: canonical resource.core requires custom members and aliases")
        if resource_dynamic_members is None:
            pass
        else:
            assert resource_compatibility_aliases is not None
            fixed = set(attribute_refs)
            aliases = {item.alias for item in resource_compatibility_aliases}
            canonicals = {item.canonical for item in resource_compatibility_aliases}
            if not canonicals.issubset(fixed) or aliases & fixed:
                raise RegistryError(f"{path}.x-defenseclaw.compatibility_aliases: fixed resource ownership mismatch")
            if aliases & set(resource_dynamic_members.reserved_keys):
                raise RegistryError(f"{path}.x-defenseclaw: aliases and additional reserved keys must be disjoint")
    if "introduced_in" not in value:
        raise RegistryError(f"{path}.introduced_in: required for every group")
    introduced_in = None
    deprecated_in = None
    removed_in = None
    if "introduced_in" in value:
        introduced_in = _string(value["introduced_in"], f"{path}.introduced_in", pattern=_ID)
    if "deprecated_in" in value:
        deprecated_in = _string(value["deprecated_in"], f"{path}.deprecated_in", pattern=_ID)
    if "removed_in" in value:
        removed_in = _string(value["removed_in"], f"{path}.removed_in", pattern=_ID)
    if removed_in is not None and deprecated_in is None:
        raise RegistryError(f"{path}.deprecated_in: required when removed_in is present")
    if stability == "deprecated" and deprecated_in is None:
        raise RegistryError(f"{path}.deprecated_in: required for deprecated groups")
    if deprecated_in is not None and stability != "deprecated":
        raise RegistryError(f"{path}.stability: must be deprecated when deprecated_in is present")
    return GroupIR(
        group_id,
        group_type,
        brief,
        stability,
        extends,
        attribute_uses,
        attribute_refs,
        (),
        event_refs,
        event_name,
        bucket,
        span_name_pattern,
        span_name_parts,
        span_kinds,
        span_status_rule,
        instrument_name,
        instrument_type,
        metric_value_type,
        metric_unit,
        metric_description,
        metric_temporality,
        metric_boundaries,
        empty_labels_reason,
        metric_projections,
        family_schema_version,
        outcome_requirement,
        allowed_outcomes,
        link_relations,
        mandatory_floor,
        route_selector,
        compatibility_profiles,
        resource_dynamic_members,
        resource_compatibility_aliases,
        legacy_bindings,
        introduced_in,
        deprecated_in,
        removed_in,
    )


def _parse_producer_identity(value: Any, path: str) -> ProducerIdentityIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(value, {"event_name", "bucket"}, {"family", "compatibility_only"}, path)
    event_name = _string(value["event_name"], f"{path}.event_name", pattern=_ID)
    bucket = _string(value["bucket"], f"{path}.bucket", pattern=_ID)
    if bucket not in EXPECTED_BUCKETS:
        raise RegistryError(f"{path}.bucket: unknown catalog-v1 bucket")
    family = None
    if "family" in value:
        family = _string(value["family"], f"{path}.family", pattern=_ID)
    compatibility_only = value.get("compatibility_only", False)
    if type(compatibility_only) is not bool:
        raise RegistryError(f"{path}.compatibility_only: expected boolean")
    if compatibility_only:
        if not event_name.startswith("legacy.audit."):
            raise RegistryError(f"{path}.event_name: compatibility-only identity must use legacy.audit.*")
        if family is not None:
            raise RegistryError(f"{path}.family: compatibility-only identity must not define a family")
    else:
        if "compatibility_only" in value:
            raise RegistryError(f"{path}.compatibility_only: omit false compatibility marker")
        if family is None:
            raise RegistryError(f"{path}.family: required for canonical identity")
    return ProducerIdentityIR(event_name, bucket, family, compatibility_only)


def _parse_producer_identity_sets(
    value: Any,
    path: str,
) -> tuple[ProducerIdentitySetIR, ...]:
    if not isinstance(value, list):
        raise RegistryError(f"{path}: expected sequence")
    result: list[ProducerIdentitySetIR] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(item, {"id", "identities"}, set(), item_path)
        set_id = _string(item["id"], f"{item_path}.id", pattern=_ID)
        if set_id in seen_ids:
            raise RegistryError(f"{item_path}.id: duplicate producer identity set")
        identities = item["identities"]
        if not isinstance(identities, list) or not identities:
            raise RegistryError(f"{item_path}.identities: expected nonempty sequence")
        parsed = tuple(
            _parse_producer_identity(identity, f"{item_path}.identities[{identity_index}]")
            for identity_index, identity in enumerate(identities)
        )
        keys = [(identity.event_name, identity.bucket) for identity in parsed]
        if len(keys) != len(set(keys)):
            raise RegistryError(f"{item_path}.identities: duplicate identity")
        seen_ids.add(set_id)
        result.append(ProducerIdentitySetIR(set_id, parsed))
    return tuple(result)


def _parse_producer_mappings(
    value: Any,
    identity_sets: dict[str, tuple[ProducerIdentityIR, ...]],
    mandatory_rule_ids: frozenset[str],
    path: str,
) -> tuple[ProducerMappingIR, ...]:
    if not isinstance(value, list):
        raise RegistryError(f"{path}: expected sequence")
    seen: set[tuple[str, str]] = set()
    mappings: list[ProducerMappingIR] = []
    used_identity_sets: set[str] = set()
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(
            item,
            {"producer", "key", "source", "event_name_policy", "severity_policy"},
            {
                "default_identity",
                "allowed_context_identity_set",
                "mandatory_rules",
                "companion_rules",
                "compatibility",
            },
            item_path,
        )
        producer = _string(item["producer"], f"{item_path}.producer", pattern=_ID)
        if producer not in {"gateway_event", "audit_action"}:
            raise RegistryError(f"{item_path}.producer: unsupported producer")
        key = _string(item["key"], f"{item_path}.key", pattern=_ID)
        identity = (producer, key)
        if identity in seen:
            raise RegistryError(f"{item_path}: duplicate producer mapping")
        seen.add(identity)
        source = _string(item["source"], f"{item_path}.source", pattern=_ID)
        policy = _string(item["event_name_policy"], f"{item_path}.event_name_policy", pattern=_ID)
        if policy not in {"fixed", "context_optional", "context_required"}:
            raise RegistryError(f"{item_path}.event_name_policy: unsupported policy")
        default = item.get("default_identity")
        context_set_id = item.get("allowed_context_identity_set")
        if policy in {"fixed", "context_optional"} and default is None:
            raise RegistryError(f"{item_path}.default_identity: required for {policy} policy")
        parsed_default = (
            _parse_producer_identity(default, f"{item_path}.default_identity") if default is not None else None
        )
        if policy == "context_required" and default is not None:
            raise RegistryError(f"{item_path}.default_identity: not allowed for context_required policy")
        if policy in {"context_optional", "context_required"} and context_set_id is None:
            raise RegistryError(f"{item_path}.allowed_context_identity_set: required for {policy} policy")
        if policy == "fixed" and context_set_id is not None:
            raise RegistryError(f"{item_path}.allowed_context_identity_set: not allowed for fixed policy")
        parsed_contexts: tuple[ProducerIdentityIR, ...] = ()
        if context_set_id is not None:
            context_set_id = _string(
                context_set_id,
                f"{item_path}.allowed_context_identity_set",
                pattern=_ID,
            )
            if context_set_id not in identity_sets:
                raise RegistryError(f"{item_path}.allowed_context_identity_set: unknown set")
            used_identity_sets.add(context_set_id)
            parsed_contexts = identity_sets[context_set_id]
        severity_policy = _string(item["severity_policy"], f"{item_path}.severity_policy", pattern=_ID)
        if severity_policy not in _SEVERITY_POLICIES:
            raise RegistryError(f"{item_path}.severity_policy: unknown policy")
        parsed_rules: dict[str, tuple[str, ...] | None] = {
            "mandatory_rules": None,
            "companion_rules": None,
        }
        for key_name in ("mandatory_rules", "companion_rules"):
            if key_name in item:
                rules = _string_list(item[key_name], f"{item_path}.{key_name}")
                allowed = mandatory_rule_ids if key_name == "mandatory_rules" else _COMPANION_RULES
                if not set(rules).issubset(allowed):
                    raise RegistryError(f"{item_path}.{key_name}: unknown rule")
                parsed_rules[key_name] = rules
        parsed_compatibility = None
        if "compatibility" in item:
            compatibility = item["compatibility"]
            if not isinstance(compatibility, dict):
                raise RegistryError(f"{item_path}.compatibility: expected mapping")
            _exact_keys(
                compatibility,
                set(),
                {"introduced_in", "legacy_event_prefix", "disposition", "removal_version"},
                f"{item_path}.compatibility",
            )
            for name, raw in compatibility.items():
                _string(raw, f"{item_path}.compatibility.{name}", pattern=_ID)
            parsed_compatibility = ProducerCompatibilityIR(
                compatibility.get("introduced_in"),
                compatibility.get("legacy_event_prefix"),
                compatibility.get("disposition"),
                compatibility.get("removal_version"),
            )
        mappings.append(
            ProducerMappingIR(
                producer,
                key,
                source,
                policy,
                severity_policy,
                parsed_rules["mandatory_rules"],
                parsed_rules["companion_rules"],
                parsed_compatibility,
                parsed_default,
                context_set_id,
                parsed_contexts,
            )
        )
    unreferenced = sorted(set(identity_sets) - used_identity_sets)
    if unreferenced:
        raise RegistryError(f"{path}: unreferenced producer identity sets {unreferenced}")
    return tuple(mappings)


def _parse_domain(
    root: Path,
    relative: str,
    expected_domain: str,
    normalizers: dict[str, NormalizerIR],
    mandatory_rule_ids: frozenset[str],
) -> tuple[DomainIR, InputDigest]:
    path, normalized = _safe_relative(
        root,
        f"schemas/telemetry/v8/{relative}",
        f"registry.imports.{relative}",
        prefix=Path("schemas/telemetry/v8"),
    )
    raw, document = _load_yaml_strict_with_bytes(path)
    _exact_keys(
        document,
        {
            "schema_version",
            "domain",
            "attributes",
            "attribute_extensions",
            "groups",
            "producer_identity_sets",
            "producer_mappings",
        },
        set(),
        normalized,
    )
    if _integer(document["schema_version"], f"{normalized}.schema_version") != 1:
        raise RegistryError(f"{normalized}.schema_version: unsupported version")
    if document["domain"] != expected_domain:
        raise RegistryError(f"{normalized}.domain: expected {expected_domain}")
    raw_attributes = document["attributes"]
    if not isinstance(raw_attributes, list):
        raise RegistryError(f"{normalized}.attributes: expected sequence")
    attributes = tuple(
        _parse_attribute_definition(item, f"{normalized}.attributes[{index}]", normalizers)
        for index, item in enumerate(raw_attributes)
    )
    raw_extensions = document["attribute_extensions"]
    if not isinstance(raw_extensions, list):
        raise RegistryError(f"{normalized}.attribute_extensions: expected sequence")
    attribute_extensions = tuple(
        _parse_attribute_extension(
            item,
            f"{normalized}.attribute_extensions[{index}]",
            normalizers,
        )
        for index, item in enumerate(raw_extensions)
    )
    raw_groups = document["groups"]
    if not isinstance(raw_groups, list):
        raise RegistryError(f"{normalized}.groups: expected sequence")
    groups = tuple(
        _parse_group(item, f"{normalized}.groups[{index}]", mandatory_rule_ids) for index, item in enumerate(raw_groups)
    )
    identity_sets = _parse_producer_identity_sets(
        document["producer_identity_sets"],
        f"{normalized}.producer_identity_sets",
    )
    identity_sets_by_id = {item.id: item.identities for item in identity_sets}
    producer_mappings = _parse_producer_mappings(
        document["producer_mappings"],
        identity_sets_by_id,
        mandatory_rule_ids,
        f"{normalized}.producer_mappings",
    )
    for label, values in (
        ("attributes", [item.id for item in attributes]),
        ("attribute_extensions", [item.ref for item in attribute_extensions]),
        ("groups", [item.id for item in groups]),
    ):
        if len(values) != len(set(values)):
            raise RegistryError(f"{normalized}.{label}: duplicate ID")
    return DomainIR(
        expected_domain,
        normalized,
        attributes,
        attribute_extensions,
        groups,
        identity_sets,
        producer_mappings,
    ), InputDigest(normalized, _sha256(raw))


def _resolved_attributes(groups: dict[str, GroupIR], group_id: str) -> frozenset[str]:
    return frozenset(use.ref for use in groups[group_id].resolved_uses)


def _rfc6901_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _json_leaf_pointers(value: Any, pointer: str = "") -> tuple[str, ...]:
    """Return the exact leaf set used by Go record field-class validation."""
    if isinstance(value, Mapping):
        if not value:
            return (pointer,)
        return tuple(
            child_pointer
            for key, child in value.items()
            for child_pointer in _json_leaf_pointers(
                child,
                pointer + "/" + _rfc6901_token(key),
            )
        )
    if isinstance(value, (list, tuple)):
        if not value:
            return (pointer,)
        return tuple(
            child_pointer
            for index, child in enumerate(value)
            for child_pointer in _json_leaf_pointers(child, pointer + f"/{index}")
        )
    return (pointer,)


def _field_class_pointer_coverage_errors(record: Any, signal: str) -> tuple[str, ...]:
    if not isinstance(record, dict):
        return ()
    payload_name = "instrument_data" if signal == "metrics" else "body"
    if payload_name not in record:
        return ()
    field_classes = record.get("field_classes")
    if not isinstance(field_classes, dict):
        return ("field_class_coverage_mismatch",)
    if any(
        not isinstance(pointer, str)
        or (pointer != "" and not pointer.startswith("/"))
        or re.search(r"~(?:[^01]|$)", pointer)
        or field_class not in _FIELD_CLASS
        for pointer, field_class in field_classes.items()
    ):
        return ("field_class_coverage_mismatch",)
    expected = set(_json_leaf_pointers(record[payload_name]))
    return () if set(field_classes) == expected else ("field_class_coverage_mismatch",)


@dataclass(slots=True)
class _ExampleErrorCollector:
    """Collect distinct stable errors without leaking example values."""

    codes: list[str]

    def add(self, code: str) -> None:
        if code not in self.codes:
            self.codes.append(code)

    def result(self) -> tuple[str, ...]:
        return tuple(self.codes)


@dataclass(frozen=True, slots=True)
class _JSONValueStats:
    members: int
    properties: int
    max_container_depth: int
    maximum_string_leaf_bytes: int
    canonical_bytes: int


def _canonical_json_number(text: str) -> str:
    """Mirror normalizeJSONNumber/normalizeExactDecimal in observability.Value."""
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", text) is None:
        raise ValueError("invalid JSON number")
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
    """Mirror encoding/json with SetEscapeHTML(false) and literal line separators."""
    result = ['"']
    short_escapes = {
        "\b": "\\b",
        "\t": "\\t",
        "\n": "\\n",
        "\f": "\\f",
        "\r": "\\r",
        '"': '\\"',
        "\\": "\\\\",
    }
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise ValueError("unpaired Unicode surrogate")
        escaped = short_escapes.get(character)
        if escaped is not None:
            result.append(escaped)
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
            raise ValueError("non-finite JSON number")
        if value == 0:
            return "0"
        return _canonical_json_number(repr(value))
    if isinstance(value, str):
        return _canonical_json_string(value)
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("JSON object key is not a string")
        return (
            "{"
            + ",".join(_canonical_json_string(key) + ":" + _canonical_json_text(value[key]) for key in sorted(value))
            + "}"
        )
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical_json_text(item) for item in value) + "]"
    raise ValueError("unsupported JSON value")


def _canonical_json_bytes(value: Any) -> bytes:
    return _canonical_json_text(value).encode("utf-8")


def _json_value_stats(value: Any) -> _JSONValueStats | None:
    """Return recursive JSON bounds using the same leaf/container model as Go Value."""
    members = 0
    properties = 0
    maximum_depth = 0
    maximum_string_leaf_bytes = 0

    def visit(item: Any, container_depth: int) -> bool:
        nonlocal members, properties, maximum_depth, maximum_string_leaf_bytes
        if item is None or type(item) in {bool, int}:
            return True
        if type(item) is float:
            return math.isfinite(item)
        if isinstance(item, str):
            try:
                encoded_length = len(item.encode("utf-8"))
            except UnicodeEncodeError:
                return False
            maximum_string_leaf_bytes = max(maximum_string_leaf_bytes, encoded_length)
            return True
        if isinstance(item, Mapping):
            maximum_depth = max(maximum_depth, container_depth)
            members += len(item)
            properties += len(item)
            return all(isinstance(key, str) and visit(child, container_depth + 1) for key, child in item.items())
        if isinstance(item, (list, tuple)):
            maximum_depth = max(maximum_depth, container_depth)
            members += len(item)
            return all(visit(child, container_depth + 1) for child in item)
        return False

    if not visit(value, 0):
        return None
    try:
        encoded = _canonical_json_bytes(value)
    except (UnicodeEncodeError, ValueError):
        return None
    return _JSONValueStats(
        members,
        properties,
        maximum_depth,
        maximum_string_leaf_bytes,
        len(encoded),
    )


def _constraints_accept(value: Any, constraints: Mapping[str, FrozenJSON]) -> bool:
    stats = _json_value_stats(value)
    if stats is None:
        return False
    enum = constraints.get("enum")
    constrained_values = value if isinstance(value, (list, tuple)) else (value,)
    if enum is not None and any(not _typed_json_contains(enum, candidate) for candidate in constrained_values):
        return False
    numeric_values = constrained_values
    if "min" in constraints and any(
        type(candidate) not in {int, float}
        or (type(candidate) is float and not math.isfinite(candidate))
        or candidate < constraints["min"]
        for candidate in numeric_values
    ):
        return False
    if "max" in constraints and any(
        type(candidate) not in {int, float}
        or (type(candidate) is float and not math.isfinite(candidate))
        or candidate > constraints["max"]
        for candidate in numeric_values
    ):
        return False
    pattern = constraints.get("pattern")
    if pattern is not None and any(
        not isinstance(candidate, str) or re.fullmatch(str(pattern), candidate) is None
        for candidate in constrained_values
    ):
        return False
    root_items = len(value) if isinstance(value, (Mapping, list, tuple)) else 1
    if root_items < constraints.get("min_items", 0):
        return False
    if "max_items" in constraints:
        observed_items = stats.members if isinstance(value, (Mapping, list, tuple)) else 1
        if observed_items > constraints["max_items"]:
            return False
    if "max_utf8_bytes" in constraints:
        observed_bytes = len(value.encode("utf-8")) if isinstance(value, str) else stats.canonical_bytes
        if observed_bytes > constraints["max_utf8_bytes"]:
            return False
    if "max_item_utf8_bytes" in constraints and stats.maximum_string_leaf_bytes > constraints["max_item_utf8_bytes"]:
        return False
    if "max_depth" in constraints and stats.max_container_depth > constraints["max_depth"]:
        return False
    if "max_properties" in constraints and stats.properties > constraints["max_properties"]:
        return False
    return True


def _normalization_accepts(value: Any, normalization: NormalizationIR) -> bool:
    return _constraints_accept(value, normalization.effective_constraints)


def _attribute_type_accepts(value: Any, field_type: str) -> bool:
    if field_type == "string":
        return isinstance(value, str)
    if field_type == "boolean":
        return type(value) is bool
    if field_type == "int64":
        return type(value) is int and -(2**63) <= value <= 2**63 - 1
    if field_type == "uint32":
        return type(value) is int and 0 <= value <= 2**32 - 1
    if field_type == "double":
        return type(value) in {int, float} and not isinstance(value, bool) and math.isfinite(value)
    if field_type == "object":
        return isinstance(value, dict)
    if field_type.endswith("[]"):
        if not isinstance(value, list):
            return False
        item_type = field_type.removesuffix("[]")
        return all(_attribute_type_accepts(item, item_type) for item in value)
    if field_type == "bytes":
        return isinstance(value, str)
    return False


def _upstream_attribute_type_accepts(value: Any, attribute: SnapshotAttribute) -> bool:
    if attribute.shape == "attribute":
        return any(_attribute_type_accepts(value, field_type) for field_type in attribute.allowed_types)
    if attribute.shape == "any_value":
        return value is not None and _json_value_stats(value) is not None
    if attribute.shape in {"indexed_prefix", "object_prefix"}:
        return isinstance(value, dict) and _json_value_stats(value) is not None
    return False


def _structural_value_accepts(value: Any, field: StructuralFieldIR) -> bool:
    type_matches = {
        "boolean": lambda item: type(item) is bool,
        "int64": lambda item: type(item) is int and -(2**63) <= item <= 2**63 - 1,
        "uint32": lambda item: type(item) is int and 0 <= item <= 2**32 - 1,
        "uint64": lambda item: type(item) is int and 0 <= item <= 2**64 - 1,
        "double": lambda item: type(item) in {int, float} and not isinstance(item, bool) and math.isfinite(item),
        "metric_number": lambda item: type(item) in {int, float} and not isinstance(item, bool) and math.isfinite(item),
        "string": lambda item: isinstance(item, str),
        "timestamp": lambda item: isinstance(item, str),
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "canonical_json": lambda item: isinstance(item, dict),
        "field_class_map": lambda item: isinstance(item, dict),
    }[field.field_type]
    if not type_matches(value):
        return False
    if field.const_present and not _typed_json_equal(value, field.const):
        return False
    if field.enum and not _typed_json_contains(field.enum, value):
        return False
    if field.normalization is not None and not _normalization_accepts(value, field.normalization):
        return False
    if field.semantic_format in {"otel-trace-id-v1", "otel-span-id-v1"}:
        if not isinstance(value, str) or set(value) == {"0"}:
            return False
    elif field.semantic_format == "w3c-tracestate-v1" and not _w3c_tracestate_accepts(value):
        return False
    return True


def _validate_structural_object_value(
    payload: Any,
    object_ir: StructuralObjectIR,
    object_lookup: Mapping[str, StructuralObjectIR],
    errors: _ExampleErrorCollector,
) -> bool:
    initial_error_count = len(errors.codes)
    if not isinstance(payload, dict):
        errors.add("structural_object_type_mismatch")
        return False
    fields = {field.name: field for field in object_ir.fields}
    if set(payload) - set(fields):
        errors.add("structural_field_not_registered")
    if any(field.required and field.name not in payload for field in object_ir.fields):
        errors.add("structural_required_field_missing")
    for name, value in payload.items():
        field = fields.get(name)
        if field is None:
            continue
        if not _structural_value_accepts(value, field):
            errors.add("structural_field_value_invalid")
            continue
        if field.object_ref is not None:
            _validate_structural_object_value(
                value,
                object_lookup[field.object_ref],
                object_lookup,
                errors,
            )
        elif field.item_ref is not None:
            for item in value:
                _validate_structural_object_value(
                    item,
                    object_lookup[field.item_ref],
                    object_lookup,
                    errors,
                )
    return len(errors.codes) == initial_error_count


def _provenance_import_rules_accept(
    payload: Any,
    rules: ProvenanceImportRulesIR,
) -> bool:
    if not isinstance(payload, dict):
        return False
    if any(field in payload and payload[field] == "" for field in rules.nonempty_string_fields):
        return False
    mode = payload.get("mode")
    has_derivation = "derivation" in payload
    derivation = payload.get("derivation")
    has_count = "source_aggregate_count" in payload
    if mode in rules.derivation_required_modes and not has_derivation:
        return False
    if mode in rules.derivation_forbidden_modes and has_derivation:
        return False
    if mode in rules.source_aggregate_count_forbidden_modes and has_count:
        return False
    if derivation in rules.source_aggregate_count_required_derivations and not has_count:
        return False
    if derivation in rules.source_aggregate_count_forbidden_derivations and has_count:
        return False
    return True


def _registered_dynamic_fields(
    payload: Any,
    group: GroupIR,
    *,
    error_code: str,
    local_attributes: Mapping[str, AttributeIR],
    upstream_extensions: Mapping[str, AttributeExtensionIR],
    upstream_attributes: Mapping[str, tuple[str, SnapshotAttribute]],
    errors: _ExampleErrorCollector,
) -> bool:
    initial_error_count = len(errors.codes)
    if not isinstance(payload, dict):
        errors.add("dynamic_attribute_object_required")
        return False
    uses = {use.ref: use for use in group.resolved_uses}
    if set(payload) - set(uses):
        errors.add(error_code)
    for reference, use in uses.items():
        if use.requirement_level == "required" and reference not in payload:
            errors.add("family_required_attribute_missing")
    for reference, value in payload.items():
        use = uses.get(reference)
        if use is None:
            continue
        local = local_attributes.get(reference)
        extension = upstream_extensions.get(reference)
        if local is not None and (
            not _attribute_type_accepts(value, local.field_type)
            or not _normalization_accepts(value, local.normalization)
        ):
            errors.add("dynamic_attribute_value_invalid")
        if extension is not None:
            upstream = upstream_attributes.get(reference)
            if (
                upstream is None
                or not _upstream_attribute_type_accepts(value, upstream[1])
                or not _normalization_accepts(value, extension.normalization)
            ):
                errors.add("dynamic_attribute_value_invalid")
        if not _constraints_accept(value, use.constraints):
            errors.add("dynamic_attribute_value_invalid")
    return len(errors.codes) == initial_error_count


def _resource_dynamic_fields(
    payload: Any,
    group: GroupIR,
    *,
    local_attributes: Mapping[str, AttributeIR],
    upstream_extensions: Mapping[str, AttributeExtensionIR],
    upstream_attributes: Mapping[str, tuple[str, SnapshotAttribute]],
    errors: _ExampleErrorCollector,
) -> bool:
    initial_error_count = len(errors.codes)
    if not isinstance(payload, dict):
        errors.add("dynamic_attribute_object_required")
        return False
    contract = group.resource_dynamic_members
    aliases = group.resource_compatibility_aliases
    if contract is None or aliases is None:
        return _registered_dynamic_fields(
            payload,
            group,
            error_code="resource_attribute_not_registered",
            local_attributes=local_attributes,
            upstream_extensions=upstream_extensions,
            upstream_attributes=upstream_attributes,
            errors=errors,
        )
    uses = {use.ref: use for use in group.resolved_uses}
    alias_sources = {item.alias: item.canonical for item in aliases}
    registered = set(uses) | set(alias_sources)
    custom: list[tuple[str, str]] = []
    normalized = {key.replace(".", "_").replace("-", "_") for key in registered | set(contract.reserved_keys)}
    for reference, value in payload.items():
        canonical = alias_sources.get(reference, reference)
        use = uses.get(canonical)
        if use is not None:
            local = local_attributes.get(canonical)
            extension = upstream_extensions.get(canonical)
            if local is not None and (
                not _attribute_type_accepts(value, local.field_type)
                or not _normalization_accepts(value, local.normalization)
            ):
                errors.add("dynamic_attribute_value_invalid")
            if extension is not None:
                upstream = upstream_attributes.get(canonical)
                if (
                    upstream is None
                    or not _upstream_attribute_type_accepts(value, upstream[1])
                    or not _normalization_accepts(value, extension.normalization)
                ):
                    errors.add("dynamic_attribute_value_invalid")
            if not _constraints_accept(value, use.constraints):
                errors.add("dynamic_attribute_value_invalid")
            continue
        if not isinstance(reference, str) or re.fullmatch(contract.key_pattern, reference) is None:
            errors.add("resource_attribute_not_registered")
            continue
        segments = tuple(item for item in re.split(r"[._-]", reference.lower()) if item)
        forbidden_segments = set(contract.forbidden_key_segments)
        if (
            reference in contract.reserved_keys
            or any(segment in forbidden_segments for segment in segments)
            or any(left == "api" and right == "key" for left, right in zip(segments, segments[1:]))
        ):
            errors.add("resource_attribute_not_registered")
            continue
        normalized_key = reference.replace(".", "_").replace("-", "_")
        if normalized_key in normalized:
            errors.add("resource_attribute_not_registered")
            continue
        normalized.add(normalized_key)
        if not isinstance(value, str):
            errors.add("dynamic_attribute_value_invalid")
            continue
        try:
            value_bytes = len(value.encode("utf-8"))
        except UnicodeEncodeError:
            errors.add("dynamic_attribute_value_invalid")
            continue
        trimmed = value.strip()
        lower = trimmed.lower()
        parsed = urllib.parse.urlsplit(trimmed)
        path_like = (
            trimmed.startswith(("/", "~/", "\\\\"))
            or lower.startswith("file://")
            or re.match(r"^[A-Za-z]:[\\/]", trimmed) is not None
        )
        credential_like = (
            "private key" in lower
            and "-----begin" in lower
            or lower.startswith(("bearer ", "basic "))
            or parsed.username is not None
        )
        if (
            not contract.min_value_utf8_bytes <= value_bytes <= contract.max_value_utf8_bytes
            or not trimmed
            or any(unicodedata.category(character) == "Cc" for character in value)
            or path_like
            or credential_like
        ):
            errors.add("dynamic_attribute_value_invalid")
            continue
        custom.append((reference, value))
    for reference, use in uses.items():
        if use.requirement_level == "required" and reference not in payload:
            errors.add("family_required_attribute_missing")
    if (
        len(custom) > contract.max_items
        or sum(len(key.encode()) + len(value.encode()) for key, value in custom) > contract.max_aggregate_utf8_bytes
    ):
        errors.add("dynamic_attribute_value_invalid")
    return len(errors.codes) == initial_error_count


def _compile_span_name_parts(pattern: str) -> tuple[SpanNamePartIR, ...] | None:
    try:
        parsed = tuple(string.Formatter().parse(pattern))
    except ValueError:
        return None
    parts: list[SpanNamePartIR] = []
    for literal, field, format_spec, conversion in parsed:
        if literal:
            if parts and parts[-1].kind == "literal":
                prior = parts[-1]
                assert prior.literal is not None
                parts[-1] = SpanNamePartIR("literal", prior.literal + literal, None)
            else:
                parts.append(SpanNamePartIR("literal", literal, None))
        if field is None:
            continue
        if not field or not _ID.fullmatch(field) or format_spec or conversion is not None:
            return None
        parts.append(SpanNamePartIR("field", None, field))
    return tuple(parts) or None


def _materialized_span_name(parts: tuple[SpanNamePartIR, ...], attributes: Mapping[str, Any]) -> str | None:
    result: list[str] = []
    for part in parts:
        if part.kind == "literal":
            assert part.literal is not None
            result.append(part.literal)
            continue
        assert part.field is not None
        if part.field not in attributes:
            return None
        result.append(str(attributes[part.field]))
    return "".join(result)


def _validate_example_record(
    signal: str,
    family: str | None,
    record: Any,
    groups: Mapping[str, GroupIR],
    structural_contract: StructuralContractIR,
    value_catalogs: tuple[ValueCatalogIR, ...],
    semantic_profiles: tuple[SemanticProfileIR, ...],
    local_attributes: Mapping[str, AttributeIR],
    upstream_extensions: Mapping[str, AttributeExtensionIR],
    upstream_attributes: Mapping[str, tuple[str, SnapshotAttribute]],
) -> tuple[str, ...]:
    errors = _ExampleErrorCollector([])
    if family is None:
        errors.add("compatibility_only_identity_has_no_family")
        return errors.result()
    group = groups.get(family)
    if group is None or group.type not in _SIGNAL_BY_GROUP_TYPE:
        errors.add("canonical_family_not_registered")
        return errors.result()
    if not isinstance(record, dict):
        errors.add("record_object_required")
        return errors.result()
    envelope_fields = {field.name: field for field in structural_contract.envelope.fields}
    if set(record) - set(envelope_fields):
        errors.add("envelope_field_not_registered")
    if any(field.required and field.name not in record for field in structural_contract.envelope.fields):
        errors.add("envelope_required_field_missing")
    for name, value in record.items():
        field = envelope_fields.get(name)
        if field is None:
            continue
        if not _structural_value_accepts(value, field):
            errors.add("envelope_field_value_invalid")
    if record.get("signal") != signal:
        errors.add("example_signal_mismatch")
    if group.bucket != record.get("bucket"):
        errors.add("family_bucket_mismatch")
    expected_event_name = (
        group.event_name if signal == "logs" else group.instrument_name if signal == "metrics" else group.id
    )
    if record.get("event_name") != expected_event_name:
        errors.add("family_event_name_mismatch")
    arm = next((candidate for candidate in structural_contract.signal_arms if candidate.signal == signal), None)
    if arm is None:
        errors.add("signal_arm_missing")
        return errors.result()
    if arm.payload_field not in record or any(name not in record for name in arm.required_fields):
        errors.add("signal_required_field_missing")
    if any(name in record for name in arm.forbidden_fields):
        errors.add("signal_forbidden_field_present")
    correlation = record.get("correlation")
    provenance = record.get("provenance")
    object_lookup = {
        "correlation": structural_contract.correlation,
        "provenance": structural_contract.provenance,
        "provenance_import": structural_contract.provenance_import,
        "trace_body": structural_contract.trace_body,
        "trace_resource": structural_contract.trace_resource,
        "trace_scope": structural_contract.trace_scope,
        "trace_status": structural_contract.trace_status,
        "trace_event": structural_contract.trace_event,
        "trace_link": structural_contract.trace_link,
        "metric_instrument_data": structural_contract.metric_instrument_data,
    }
    _validate_structural_object_value(
        correlation,
        structural_contract.correlation,
        object_lookup,
        errors,
    )
    _validate_structural_object_value(
        provenance,
        structural_contract.provenance,
        object_lookup,
        errors,
    )
    if (
        isinstance(provenance, dict)
        and "import" in provenance
        and not _provenance_import_rules_accept(
            provenance["import"],
            structural_contract.provenance_import_rules,
        )
    ):
        errors.add("provenance_import_rule_invalid")
    if not isinstance(correlation, dict) or any(name not in correlation for name in arm.required_correlation_fields):
        errors.add("trace_correlation_identity_missing")
    if record.get("outcome") not in (group.allowed_outcomes or ()):
        if group.outcome_requirement == "required" or "outcome" in record:
            errors.add("family_outcome_invalid")
    if group.outcome_requirement == "forbidden" and "outcome" in record:
        errors.add("family_outcome_invalid")

    if signal == "logs":
        _registered_dynamic_fields(
            record.get("body"),
            group,
            error_code="finding_body_field_not_registered",
            local_attributes=local_attributes,
            upstream_extensions=upstream_extensions,
            upstream_attributes=upstream_attributes,
            errors=errors,
        )
    elif signal == "metrics":
        instrument = record.get("instrument_data")
        _validate_structural_object_value(
            instrument,
            structural_contract.metric_instrument_data,
            object_lookup,
            errors,
        )
        if isinstance(instrument, dict):
            _registered_dynamic_fields(
                instrument.get("attributes"),
                group,
                error_code="metric_label_not_registered",
                local_attributes=local_attributes,
                upstream_extensions=upstream_extensions,
                upstream_attributes=upstream_attributes,
                errors=errors,
            )
            metric_value = instrument.get("value")
            if group.metric_value_type == "int64" and (
                type(metric_value) is not int or not -(2**63) <= metric_value <= 2**63 - 1
            ):
                errors.add("metric_value_type_mismatch")
            if group.metric_value_type == "double" and (
                type(metric_value) not in {int, float}
                or isinstance(metric_value, bool)
                or not math.isfinite(metric_value)
            ):
                errors.add("metric_value_type_mismatch")
    else:
        body = record.get("body")
        _validate_structural_object_value(
            body,
            structural_contract.trace_body,
            object_lookup,
            errors,
        )
        if isinstance(body, dict):
            attributes = body.get("attributes")
            _registered_dynamic_fields(
                attributes,
                group,
                error_code="span_attribute_not_registered",
                local_attributes=local_attributes,
                upstream_extensions=upstream_extensions,
                upstream_attributes=upstream_attributes,
                errors=errors,
            )
            if body.get("kind") not in (group.span_kinds or ()):
                errors.add("span_kind_mismatch")
            materialized_name = (
                _materialized_span_name(group.span_name_parts, attributes)
                if group.span_name_parts is not None and isinstance(attributes, Mapping)
                else None
            )
            if materialized_name is None or record.get("span_name") != materialized_name:
                errors.add("span_name_mismatch")
            if isinstance(attributes, Mapping):
                for envelope_name, attribute_name in (
                    ("bucket", "defenseclaw.bucket"),
                    ("source", "defenseclaw.source"),
                    ("outcome", "defenseclaw.outcome"),
                ):
                    if attribute_name in attributes and (
                        envelope_name not in record
                        or not _typed_json_equal(attributes[attribute_name], record[envelope_name])
                    ):
                        errors.add("span_envelope_attribute_mismatch")
                resolved_attribute_ids = {use.ref for use in group.resolved_uses}
                if "defenseclaw.span.family" in resolved_attribute_ids and not _typed_json_equal(
                    attributes.get("defenseclaw.span.family"), family
                ):
                    errors.add("span_family_attribute_mismatch")
                if "defenseclaw.span.family_schema_version" in resolved_attribute_ids and not _typed_json_equal(
                    attributes.get("defenseclaw.span.family_schema_version"),
                    group.family_schema_version,
                ):
                    errors.add("span_family_schema_version_mismatch")
                if "defenseclaw.config.generation" in resolved_attribute_ids and not _typed_json_equal(
                    attributes.get("defenseclaw.config.generation"),
                    provenance.get("config_generation") if isinstance(provenance, dict) else None,
                ):
                    errors.add("span_config_generation_mismatch")
            for relation in structural_contract.trace_relations:
                left = body.get(relation.left)
                right = body.get(relation.right)
                if (
                    relation.kind == "less_than_or_equal"
                    and type(left) in {int, float}
                    and type(right) in {int, float}
                    and left > right
                ):
                    errors.add("trace_time_order_invalid")
            resource = body.get("resource")
            scope = body.get("scope")
            resource_group = groups["resource.core"]
            scope_group = groups["scope.core"]
            _resource_dynamic_fields(
                resource.get("attributes") if isinstance(resource, dict) else None,
                resource_group,
                local_attributes=local_attributes,
                upstream_extensions=upstream_extensions,
                upstream_attributes=upstream_attributes,
                errors=errors,
            )
            scope_attributes = scope.get("attributes") if isinstance(scope, dict) else None
            _registered_dynamic_fields(
                scope_attributes,
                scope_group,
                error_code="scope_attribute_not_registered",
                local_attributes=local_attributes,
                upstream_extensions=upstream_extensions,
                upstream_attributes=upstream_attributes,
                errors=errors,
            )
            profile = semantic_profiles[0]
            if (
                not isinstance(scope_attributes, dict)
                or not _typed_json_equal(
                    scope_attributes.get("defenseclaw.trace.schema_version"),
                    profile.trace_schema_version,
                )
                or not _typed_json_equal(
                    scope_attributes.get("defenseclaw.semantic_profile"),
                    profile.id,
                )
            ):
                errors.add("scope_semantic_profile_mismatch")
            events = body.get("events", [])
            if isinstance(events, list):
                for event in events:
                    if not isinstance(event, dict):
                        continue
                    event_group = groups.get("event." + str(event.get("name", "")))
                    if event_group is None or event.get("name") not in (group.event_refs or ()):
                        errors.add("span_event_not_registered")
                        continue
                    _registered_dynamic_fields(
                        event.get("attributes"),
                        event_group,
                        error_code="span_event_attribute_not_registered",
                        local_attributes=local_attributes,
                        upstream_extensions=upstream_extensions,
                        upstream_attributes=upstream_attributes,
                        errors=errors,
                    )
            links = body.get("links", [])
            if isinstance(links, list):
                for link in links:
                    if not isinstance(link, dict):
                        continue
                    _registered_dynamic_fields(
                        link.get("attributes"),
                        groups["link.core"],
                        error_code="span_link_attribute_not_registered",
                        local_attributes=local_attributes,
                        upstream_extensions=upstream_extensions,
                        upstream_attributes=upstream_attributes,
                        errors=errors,
                    )
                    link_attributes = link.get("attributes")
                    if not isinstance(link_attributes, dict) or link_attributes.get(
                        "defenseclaw.link.relation"
                    ) not in (group.link_relations or ()):
                        errors.add("span_link_relation_invalid")

    for catalog in value_catalogs:
        instrument = record.get("instrument_data")
        body = record.get("body")
        payload = (
            instrument.get("attributes")
            if signal == "metrics" and isinstance(instrument, dict)
            else body.get("attributes", body)
            if isinstance(body, dict)
            else None
        )
        if not isinstance(payload, dict):
            continue
        paired_value = payload.get(catalog.paired_value_attribute)
        paired_code = payload.get(catalog.code_attribute)
        if paired_value is not None and paired_code is not None:
            if not isinstance(paired_value, str):
                # The registered attribute validator owns the stable type
                # error.  Never use an unhashable malformed value as a lookup
                # key while evaluating the cross-field relationship.
                continue
            expected_code = {entry.value: entry.code for entry in catalog.entries}.get(paired_value)
            if not _typed_json_equal(expected_code, paired_code):
                errors.add("lifecycle_phase_code_mismatch")
    return errors.result()


def _decode_rfc6901(pointer: str) -> list[str]:
    if not pointer.startswith("/"):
        raise RegistryError("example mutation path must be an RFC6901 pointer")
    if re.search(r"~(?:[^01]|$)", pointer):
        raise RegistryError("example mutation path contains an invalid RFC6901 escape")
    return [token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/")]


def _apply_example_mutation(target: dict[str, Any], change: ExampleMutationChangeIR) -> None:
    tokens = _decode_rfc6901(change.path)
    current: Any = target
    for token in tokens[:-1]:
        if isinstance(current, dict):
            if token not in current:
                raise RegistryError("example mutation path does not resolve")
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit() or int(token) >= len(current):
                raise RegistryError("example mutation path does not resolve")
            current = current[int(token)]
        else:
            raise RegistryError("example mutation path does not resolve")
    leaf = tokens[-1]
    if isinstance(current, dict):
        exists = leaf in current
        if change.op == "add":
            if exists:
                raise RegistryError("example mutation add target already exists")
            current[leaf] = _thaw_json(change.value)
        elif change.op == "replace":
            if not exists:
                raise RegistryError("example mutation replace target does not exist")
            current[leaf] = _thaw_json(change.value)
        else:
            if not exists:
                raise RegistryError("example mutation remove target does not exist")
            del current[leaf]
        return
    if not isinstance(current, list) or not leaf.isdigit():
        raise RegistryError("example mutation path does not resolve")
    index = int(leaf)
    if change.op == "add":
        if index > len(current):
            raise RegistryError("example mutation add index is out of range")
        current.insert(index, _thaw_json(change.value))
    elif change.op == "replace":
        if index >= len(current):
            raise RegistryError("example mutation replace index is out of range")
        current[index] = _thaw_json(change.value)
    else:
        if index >= len(current):
            raise RegistryError("example mutation remove index is out of range")
        del current[index]


def _thaw_json(value: FrozenJSON) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _validate_example_field_classes(
    record: Any,
    signal: str,
    family: str,
    path: str,
    groups: dict[str, GroupIR],
    local_attributes: dict[str, AttributeIR],
    upstream_extensions: dict[str, AttributeExtensionIR],
    structural_contract: StructuralContractIR,
) -> Mapping[str, str]:
    if not isinstance(record, dict):
        raise RegistryError(f"{path}: expected mapping")
    field_classes = record.get("field_classes")
    if not isinstance(field_classes, dict):
        raise RegistryError(f"{path}.field_classes: expected mapping")
    group = groups[family]
    resolved = _resolved_attributes(groups, family)
    reverse_projection: dict[str, str] = {}
    for projection in group.metric_projections:
        if projection.profile == "local-observability-v1":
            reverse_projection = {label: reference for reference, label in projection.mappings}
    expected: dict[str, str] = {}

    def add_registered_fields(
        dynamic: Any,
        references: frozenset[str],
        prefix: str,
        projections: Mapping[str, str] = MappingProxyType({}),
        empty_container_class: str = "metadata",
        resource_group: GroupIR | None = None,
    ) -> None:
        if not isinstance(dynamic, dict):
            raise RegistryError(f"{path}: valid {signal} example has no dynamic attribute mapping")
        if not dynamic:
            expected[prefix.removesuffix("/")] = empty_container_class
            return
        for wire_name in dynamic:
            if not isinstance(wire_name, str):
                raise RegistryError(f"{path}: dynamic attribute names must be strings")
            reference = projections.get(wire_name, wire_name)
            if reference not in references:
                alias_sources = (
                    {item.alias: item.canonical for item in (resource_group.resource_compatibility_aliases or ())}
                    if resource_group is not None
                    else {}
                )
                alias_reference = alias_sources.get(reference)
                if alias_reference in references:
                    reference = alias_reference
                elif resource_group is not None and resource_group.resource_dynamic_members is not None:
                    field_class = resource_group.resource_dynamic_members.field_class
                    base_pointer = prefix + _rfc6901_token(wire_name)
                    for pointer in _json_leaf_pointers(dynamic[wire_name], base_pointer):
                        expected[pointer] = field_class
                    continue
                else:
                    raise RegistryError(f"{path}: unregistered dynamic field {wire_name!r}")
            local = local_attributes.get(reference)
            extension = upstream_extensions.get(reference)
            if local is not None:
                field_class = local.field_class
            elif extension is not None:
                field_class = extension.field_class
            else:
                raise RegistryError(f"{path}: dynamic field {wire_name!r} has no privacy metadata")
            base_pointer = prefix + _rfc6901_token(wire_name)
            for pointer in _json_leaf_pointers(dynamic[wire_name], base_pointer):
                expected[pointer] = field_class

    if signal == "logs":
        body_field = _structural_field(structural_contract.envelope, "body")
        add_registered_fields(
            record.get("body"),
            resolved,
            "/",
            reverse_projection,
            body_field.field_class or "metadata",
        )
    elif signal == "metrics":
        instrument = record.get("instrument_data")
        if not isinstance(instrument, dict):
            raise RegistryError(f"{path}: valid metrics example has no instrument_data")
        value_field = _structural_field(structural_contract.metric_instrument_data, "value")
        if "value" in instrument and value_field.field_class is not None:
            expected["/value"] = value_field.field_class
        metric_attributes_field = _structural_field(
            structural_contract.metric_instrument_data,
            "attributes",
        )
        add_registered_fields(
            instrument.get("attributes"),
            resolved,
            "/attributes/",
            reverse_projection,
            metric_attributes_field.field_class or "metadata",
        )
    else:
        body = record.get("body")
        if not isinstance(body, dict):
            raise RegistryError(f"{path}: valid traces example has no body")
        structural_objects = {
            "trace_status": structural_contract.trace_status,
            "trace_resource": structural_contract.trace_resource,
            "trace_scope": structural_contract.trace_scope,
            "trace_event": structural_contract.trace_event,
            "trace_link": structural_contract.trace_link,
        }

        def add_structural_object(
            payload: Any,
            object_ir: StructuralObjectIR,
            prefix: str,
        ) -> None:
            if not isinstance(payload, dict):
                raise RegistryError(f"{path}: structural object {object_ir.id} must be a mapping")
            fields = {field.name: field for field in object_ir.fields}
            for name, child in payload.items():
                field = fields.get(name)
                if field is None:
                    raise RegistryError(f"{path}: unregistered structural field {name!r}")
                pointer = prefix + "/" + _rfc6901_token(name)
                if field.object_ref is not None:
                    if isinstance(child, dict) and not child:
                        expected[pointer] = field.field_class or "metadata"
                    else:
                        add_structural_object(child, structural_objects[field.object_ref], pointer)
                elif field.item_ref is not None:
                    if not isinstance(child, list):
                        raise RegistryError(f"{path}: structural array {name!r} must be a sequence")
                    if not child:
                        expected[pointer] = field.field_class or "metadata"
                    for index, item in enumerate(child):
                        add_structural_object(
                            item,
                            structural_objects[field.item_ref],
                            f"{pointer}/{index}",
                        )
                elif name != "attributes" and field.field_class is not None:
                    expected[pointer] = field.field_class

        add_structural_object(body, structural_contract.trace_body, "")
        trace_attributes_field = _structural_field(structural_contract.trace_body, "attributes")
        add_registered_fields(
            body.get("attributes"),
            resolved,
            "/attributes/",
            empty_container_class=trace_attributes_field.field_class or "metadata",
        )
        resource = body.get("resource")
        if not isinstance(resource, dict):
            raise RegistryError(f"{path}: valid trace example has no resource")
        resource_group = groups.get("resource.core")
        if resource_group is None:
            raise RegistryError(f"{path}: resource.core is not registered")
        add_registered_fields(
            resource.get("attributes"),
            _resolved_attributes(groups, "resource.core"),
            "/resource/attributes/",
            empty_container_class=(
                _structural_field(structural_contract.trace_resource, "attributes").field_class or "metadata"
            ),
            resource_group=resource_group,
        )
        scope = body.get("scope")
        if not isinstance(scope, dict) or not isinstance(scope.get("attributes"), dict):
            raise RegistryError(f"{path}: valid trace example has no scope attributes")
        add_registered_fields(
            scope["attributes"],
            _resolved_attributes(groups, "scope.core"),
            "/scope/attributes/",
            empty_container_class=(
                _structural_field(structural_contract.trace_scope, "attributes").field_class or "metadata"
            ),
        )
        for index, event in enumerate(body.get("events", [])):
            if not isinstance(event, dict):
                raise RegistryError(f"{path}: trace event must be a mapping")
            event_group = groups.get("event." + str(event.get("name", "")))
            if event_group is None:
                raise RegistryError(f"{path}: trace event has no registered family")
            add_registered_fields(
                event.get("attributes"),
                _resolved_attributes(groups, event_group.id),
                f"/events/{index}/attributes/",
                empty_container_class=(
                    _structural_field(structural_contract.trace_event, "attributes").field_class or "metadata"
                ),
            )
        for index, link in enumerate(body.get("links", [])):
            if not isinstance(link, dict):
                raise RegistryError(f"{path}: trace link must be a mapping")
            add_registered_fields(
                link.get("attributes"),
                _resolved_attributes(groups, "link.core"),
                f"/links/{index}/attributes/",
                empty_container_class=(
                    _structural_field(structural_contract.trace_link, "attributes").field_class or "metadata"
                ),
            )
    observed: dict[str, str] = {}
    for pointer, field_class in field_classes.items():
        if not isinstance(pointer, str) or (pointer != "" and not pointer.startswith("/")):
            raise RegistryError(f"{path}.field_classes: keys must be RFC6901 pointers")
        if field_class not in _FIELD_CLASS:
            raise RegistryError(f"{path}.field_classes.{pointer}: unknown field class")
        observed[pointer] = field_class
    if observed != expected:
        missing = sorted(expected.keys() - observed.keys())
        extra = sorted(observed.keys() - expected.keys())
        mismatched = sorted(
            pointer for pointer in expected.keys() & observed.keys() if expected[pointer] != observed[pointer]
        )
        raise RegistryError(
            f"{path}.field_classes: coverage mismatch missing={missing} extra={extra} mismatched={mismatched}"
        )
    return MappingProxyType(dict(observed))


def _parse_builder_fact_map(value: Any, path: str) -> tuple[BuilderFactIR, ...]:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    facts: list[BuilderFactIR] = []
    for raw_fact in sorted(value):
        fact = _string(raw_fact, f"{path}: fact name", pattern=_ID)
        fact_value = value[raw_fact]
        if type(fact_value) is not bool:
            raise RegistryError(f"{path}.{fact}: expected boolean")
        facts.append(BuilderFactIR(fact, fact_value))
    return tuple(facts)


def _builder_fact_values(facts: tuple[BuilderFactIR, ...]) -> dict[str, bool]:
    return {fact.fact: fact.value for fact in facts}


def _example_condition_use_contexts(
    signal: str,
    family: GroupIR,
    record: Mapping[str, Any],
    groups: Mapping[str, GroupIR],
) -> tuple[tuple[ResolvedAttributeUseIR, Mapping[str, Any]], ...]:
    result: list[tuple[ResolvedAttributeUseIR, Mapping[str, Any]]] = []
    body = record.get("body")
    instrument = record.get("instrument_data")
    if signal == "logs":
        family_attributes = body
    elif signal == "traces" and isinstance(body, Mapping):
        family_attributes = body.get("attributes")
    elif signal == "metrics" and isinstance(instrument, Mapping):
        family_attributes = instrument.get("attributes")
    else:
        family_attributes = None
    if not isinstance(family_attributes, Mapping):
        raise RegistryError("valid example has no family attribute object for builder facts")
    result.extend((use, family_attributes) for use in family.resolved_uses if use.conditional is not None)
    if signal != "traces":
        return tuple(result)
    assert isinstance(body, Mapping)
    for key, group_id in (("resource", "resource.core"), ("scope", "scope.core")):
        container = body.get(key)
        attributes = container.get("attributes") if isinstance(container, Mapping) else None
        if not isinstance(attributes, Mapping):
            raise RegistryError(f"valid trace example has no {key} attributes for builder facts")
        result.extend((use, attributes) for use in groups[group_id].resolved_uses if use.conditional is not None)
    events = body.get("events", ())
    if isinstance(events, list):
        for event in events:
            if not isinstance(event, Mapping):
                continue
            event_group = groups.get("event." + str(event.get("name", "")))
            attributes = event.get("attributes")
            if event_group is not None and isinstance(attributes, Mapping):
                result.extend((use, attributes) for use in event_group.resolved_uses if use.conditional is not None)
    links = body.get("links", ())
    if isinstance(links, list):
        for link in links:
            attributes = link.get("attributes") if isinstance(link, Mapping) else None
            if isinstance(attributes, Mapping):
                result.extend(
                    (use, attributes) for use in groups["link.core"].resolved_uses if use.conditional is not None
                )
    return tuple(result)


def _parse_explicit_builder_context(
    value: Any,
    path: str,
    *,
    signal: str,
    family: GroupIR,
    record: Mapping[str, Any],
    groups: Mapping[str, GroupIR],
    conditions: Mapping[str, ConditionIR],
    mandatory_rules: Mapping[str, MandatoryRuleIR],
) -> BuilderContextIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(
        value,
        {"inheritance", "occurrence", "condition_facts", "mandatory_facts"},
        set(),
        path,
    )
    inheritance = value["inheritance"]
    if not isinstance(inheritance, dict):
        raise RegistryError(f"{path}.inheritance: expected mapping")
    _exact_keys(inheritance, {"mode"}, set(), f"{path}.inheritance")
    if inheritance["mode"] != "explicit":
        raise RegistryError(f"{path}.inheritance.mode: valid example requires explicit")
    occurrence = value["occurrence"]
    if not isinstance(occurrence, dict):
        raise RegistryError(f"{path}.occurrence: expected mapping")
    _exact_keys(occurrence, {"timestamp", "record_id"}, set(), f"{path}.occurrence")
    timestamp = _string(occurrence["timestamp"], f"{path}.occurrence.timestamp")
    record_id = _string(occurrence["record_id"], f"{path}.occurrence.record_id")
    if timestamp != record.get("timestamp") or record_id != record.get("record_id"):
        raise RegistryError(f"{path}.occurrence: must equal the record timestamp and record_id")
    condition_facts = _parse_builder_fact_map(value["condition_facts"], f"{path}.condition_facts")
    condition_values = _builder_fact_values(condition_facts)
    use_contexts = _example_condition_use_contexts(signal, family, record, groups)
    referenced_conditions = {use.conditional for use, _ in use_contexts if use.conditional is not None}
    unknown_conditions = sorted(referenced_conditions - conditions.keys())
    if unknown_conditions:
        raise RegistryError(f"{path}.condition_facts: unknown condition ID {unknown_conditions[0]!r}")
    expected_condition_facts = {
        conditions[condition_id].enforcement.fact
        for condition_id in referenced_conditions
        if conditions[condition_id].enforcement.kind == "builder_fact"
    }
    if None in expected_condition_facts:
        raise RegistryError(f"{path}.condition_facts: builder-fact condition has no fact")
    if set(condition_values) != expected_condition_facts:
        missing = sorted(expected_condition_facts - set(condition_values))
        extra = sorted(set(condition_values) - expected_condition_facts)
        raise RegistryError(f"{path}.condition_facts: coverage mismatch missing={missing} extra={extra}")
    for use, attributes in use_contexts:
        assert use.conditional is not None
        condition = conditions[use.conditional]
        if condition.enforcement.kind == "builder_fact":
            fact = condition.enforcement.fact
            if fact is None:
                raise RegistryError(f"{path}.condition_facts: builder-fact condition has no fact")
            fact_value = condition_values[fact]
            source_path = f"{path}.condition_facts.{fact}"
        elif condition.enforcement.kind == "boolean_attribute":
            source_ref = condition.enforcement.attribute
            fact_value = attributes.get(source_ref) if source_ref is not None else None
            if fact_value is None:
                fact_value = False
            elif type(fact_value) is not bool:
                raise RegistryError(f"{path}: condition {condition.id} requires boolean source attribute {source_ref}")
            source_path = f"{path}.attributes.{source_ref}"
        else:
            raise RegistryError(f"{path}: condition {condition.id} has unsupported enforcement")
        present = use.ref in attributes
        if fact_value and use.requirement_level == "conditional" and not present:
            raise RegistryError(f"{source_path}: true requires {use.ref}")
        if not fact_value and condition.false_requirement == "forbidden" and present:
            raise RegistryError(f"{source_path}: false forbids {use.ref}")

    mandatory_facts = _parse_builder_fact_map(value["mandatory_facts"], f"{path}.mandatory_facts")
    mandatory_values = _builder_fact_values(mandatory_facts)
    rules = (family.mandatory_floor or ()) if signal == "logs" else ()
    expected_mandatory_facts = {
        mandatory_rules[rule_id].enforcement.fact
        for rule_id in rules
        if mandatory_rules[rule_id].enforcement.kind == "builder_fact"
    }
    if set(mandatory_values) != expected_mandatory_facts:
        missing = sorted(expected_mandatory_facts - set(mandatory_values))
        extra = sorted(set(mandatory_values) - expected_mandatory_facts)
        raise RegistryError(f"{path}.mandatory_facts: coverage mismatch missing={missing} extra={extra}")
    mandatory = any(
        rule.enforcement.value is True
        or (
            rule.enforcement.kind == "builder_fact"
            and rule.enforcement.fact is not None
            and mandatory_values[rule.enforcement.fact]
        )
        for rule in (mandatory_rules[rule_id] for rule_id in rules)
    )
    if signal == "logs" and record.get("mandatory") is not mandatory:
        raise RegistryError(f"{path}.mandatory_facts: derived mandatory does not equal record.mandatory")
    return BuilderContextIR(
        BuilderContextInheritanceIR("explicit", None),
        BuilderOccurrenceIR(timestamp, record_id),
        condition_facts,
        mandatory_facts,
    )


def _parse_inherited_builder_context(value: Any, path: str, base_example: str) -> BuilderContextIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(value, {"inheritance"}, set(), path)
    inheritance = value["inheritance"]
    if not isinstance(inheritance, dict):
        raise RegistryError(f"{path}.inheritance: expected mapping")
    _exact_keys(inheritance, {"mode", "base_example"}, set(), f"{path}.inheritance")
    if inheritance["mode"] != "exact_base":
        raise RegistryError(f"{path}.inheritance.mode: invalid example requires exact_base")
    inherited_base = _string(inheritance["base_example"], f"{path}.inheritance.base_example", pattern=_ID)
    if inherited_base != base_example:
        raise RegistryError(f"{path}.inheritance.base_example: must equal example base_example")
    return BuilderContextIR(BuilderContextInheritanceIR("exact_base", inherited_base), None, (), ())


def _parse_examples(
    root: Path,
    relative: str,
    group_signals: dict[str, str],
    groups: dict[str, GroupIR],
    local_attributes: dict[str, AttributeIR],
    upstream_extensions: dict[str, AttributeExtensionIR],
    upstream_attributes: dict[str, tuple[str, SnapshotAttribute]],
    structural_contract: StructuralContractIR,
    conditions: tuple[ConditionIR, ...],
    mandatory_rule_catalog: MandatoryRuleCatalogIR,
    value_catalogs: tuple[ValueCatalogIR, ...],
    semantic_profiles: tuple[SemanticProfileIR, ...],
) -> tuple[tuple[ExampleIR, ...], InputDigest]:
    path, normalized = _safe_relative(
        root,
        f"schemas/telemetry/v8/{relative}",
        "registry.examples",
        prefix=Path("schemas/telemetry/v8"),
    )
    raw, document = _load_yaml_strict_with_bytes(path)
    _exact_keys(document, {"schema_version", "examples"}, set(), normalized)
    if _integer(document["schema_version"], f"{normalized}.schema_version") != 1:
        raise RegistryError(f"{normalized}.schema_version: unsupported version")
    examples = document["examples"]
    if not isinstance(examples, list):
        raise RegistryError(f"{normalized}.examples: expected sequence")
    seen: set[str] = set()
    parsed_examples: list[ExampleIR] = []
    raw_vectors: dict[str, dict[str, Any]] = {}
    validity_by_id: dict[str, bool] = {}
    builder_contexts_by_id: dict[str, BuilderContextIR] = {}
    conditions_by_id = {condition.id: condition for condition in conditions}
    mandatory_rules_by_id = {rule.id: rule for rule in mandatory_rule_catalog.rules}
    for index, item in enumerate(examples):
        item_path = f"{normalized}.examples[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(
            item,
            {"id", "valid", "signal", "description", "builder_context"},
            {"family", "record", "expected_error", "base_example", "mutation"},
            item_path,
        )
        example_id = _string(item["id"], f"{item_path}.id", pattern=_EXAMPLE_ID)
        if example_id in _RESERVED_DOS_DEVICE_IDS:
            raise RegistryError(f"{item_path}.id: platform-reserved example id")
        if example_id in seen:
            raise RegistryError(f"{item_path}.id: duplicate example")
        seen.add(example_id)
        if type(item["valid"]) is not bool:
            raise RegistryError(f"{item_path}.valid: expected boolean")
        signal = _string(item["signal"], f"{item_path}.signal")
        if signal not in {"logs", "traces", "metrics"}:
            raise RegistryError(f"{item_path}.signal: unsupported signal")
        family = None
        if "family" in item:
            family = _string(item["family"], f"{item_path}.family", pattern=_ID)
            if item["valid"] and family not in group_signals:
                raise RegistryError(f"{item_path}.family: unknown family")
            if item["valid"] and group_signals[family] != signal:
                raise RegistryError(f"{item_path}.signal: family belongs to another signal")
        description = _string(item["description"], f"{item_path}.description")
        if item["valid"]:
            if (
                family is None
                or "record" not in item
                or any(key in item for key in ("expected_error", "base_example", "mutation"))
            ):
                raise RegistryError(f"{item_path}: valid example requires family and record only")
        elif not all(key in item for key in ("record", "expected_error", "base_example", "mutation")):
            raise RegistryError(
                f"{item_path}: invalid example requires record, expected_error, base_example, and mutation"
            )
        expected_error = None
        if "expected_error" in item:
            expected_error = _string(
                item["expected_error"],
                f"{item_path}.expected_error",
                pattern=_ID,
            )
        if "record" in item:
            _validate_json_compatible(item["record"], f"{item_path}.record")
        base_example = None
        mutation_ir = None
        builder_context: BuilderContextIR
        if not item["valid"]:
            base_example = _string(item["base_example"], f"{item_path}.base_example", pattern=_ID)
            if base_example not in raw_vectors or not validity_by_id[base_example]:
                raise RegistryError(f"{item_path}.base_example: must reference an earlier valid example")
            builder_context = _parse_inherited_builder_context(
                item["builder_context"],
                f"{item_path}.builder_context",
                base_example,
            )
            if builder_contexts_by_id[base_example].inheritance.mode != "explicit":
                raise RegistryError(f"{item_path}.builder_context: exact_base must name an explicit valid context")
            mutation = item["mutation"]
            if not isinstance(mutation, dict):
                raise RegistryError(f"{item_path}.mutation: expected mapping")
            _exact_keys(mutation, {"kind", "changes"}, set(), f"{item_path}.mutation")
            mutation_kind = _string(mutation["kind"], f"{item_path}.mutation.kind", pattern=_ID)
            if mutation_kind != expected_error:
                raise RegistryError(f"{item_path}.mutation.kind: must equal expected_error")
            changes_raw = mutation["changes"]
            if not isinstance(changes_raw, list) or not changes_raw:
                raise RegistryError(f"{item_path}.mutation.changes: expected nonempty sequence")
            changes: list[ExampleMutationChangeIR] = []
            seen_paths: set[str] = set()
            for change_index, change in enumerate(changes_raw):
                change_path = f"{item_path}.mutation.changes[{change_index}]"
                if not isinstance(change, dict):
                    raise RegistryError(f"{change_path}: expected mapping")
                _exact_keys(change, {"op", "path"}, {"value"}, change_path)
                op = _string(change["op"], f"{change_path}.op", pattern=_ID)
                if op not in {"add", "replace", "remove"}:
                    raise RegistryError(f"{change_path}.op: unsupported mutation operation")
                pointer = _string(change["path"], f"{change_path}.path")
                pointer_tokens = _decode_rfc6901(pointer)
                if pointer_tokens[0] not in {"signal", "family", "record"}:
                    raise RegistryError(f"{change_path}.path: root must be signal, family, or record")
                if pointer in seen_paths:
                    raise RegistryError(f"{item_path}.mutation.changes: duplicate path")
                value_present = "value" in change
                if (op in {"add", "replace"}) != value_present:
                    raise RegistryError(f"{change_path}.value: required for add/replace and forbidden for remove")
                frozen_value = None
                if value_present:
                    _validate_json_compatible(change["value"], f"{change_path}.value")
                    frozen_value = _freeze_json(change["value"])
                changes.append(ExampleMutationChangeIR(op, pointer, value_present, frozen_value))
                seen_paths.add(pointer)
            mutation_ir = ExampleMutationIR(mutation_kind, tuple(changes))
            base_vector = raw_vectors[base_example]
            derived = copy.deepcopy(base_vector)
            for change in changes:
                _apply_example_mutation(derived, change)
            observed_vector: dict[str, Any] = {"signal": signal, "record": item["record"]}
            if family is not None:
                observed_vector["family"] = family
            if not _typed_json_equal(derived, observed_vector):
                raise RegistryError(f"{item_path}.mutation: derived vector does not equal checked-in invalid example")
        # Invalid examples are negative test vectors. Their raw record is
        # preserved, but any embedded field_classes map is deliberately not
        # promoted into authoritative compiler metadata.
        field_classes: Mapping[str, str] = MappingProxyType({})
        if item["valid"]:
            assert family is not None
            errors = _validate_example_record(
                signal,
                family,
                item["record"],
                groups,
                structural_contract,
                value_catalogs,
                semantic_profiles,
                local_attributes,
                upstream_extensions,
                upstream_attributes,
            )
            if errors:
                raise RegistryError(f"{item_path}: valid example failed with {errors!r}")
            field_classes = _validate_example_field_classes(
                item["record"],
                signal,
                family,
                f"{item_path}.record",
                groups,
                local_attributes,
                upstream_extensions,
                structural_contract,
            )
            builder_context = _parse_explicit_builder_context(
                item["builder_context"],
                f"{item_path}.builder_context",
                signal=signal,
                family=groups[family],
                record=item["record"],
                groups=groups,
                conditions=conditions_by_id,
                mandatory_rules=mandatory_rules_by_id,
            )
        else:
            errors = _validate_example_record(
                signal,
                family,
                item["record"],
                groups,
                structural_contract,
                value_catalogs,
                semantic_profiles,
                local_attributes,
                upstream_extensions,
                upstream_attributes,
            )
            errors = tuple(dict.fromkeys((*errors, *_field_class_pointer_coverage_errors(item["record"], signal))))
            classification_unavailable = {
                "finding_body_field_not_registered",
                "metric_label_not_registered",
                "resource_attribute_not_registered",
                "scope_attribute_not_registered",
                "span_attribute_not_registered",
                "span_event_attribute_not_registered",
                "span_event_not_registered",
                "span_link_attribute_not_registered",
            }
            if (
                family in groups
                and group_signals.get(family) == signal
                and classification_unavailable.isdisjoint(errors)
            ):
                try:
                    _validate_example_field_classes(
                        item["record"],
                        signal,
                        family,
                        f"{item_path}.record",
                        groups,
                        local_attributes,
                        upstream_extensions,
                        structural_contract,
                    )
                except RegistryError as exc:
                    if "field_classes: coverage mismatch" in str(exc):
                        errors = tuple(dict.fromkeys((*errors, "field_class_classification_mismatch")))
                    else:
                        raise
            if not errors:
                raise RegistryError(f"{item_path}: invalid example unexpectedly validates")
            if errors != (expected_error,):
                raise RegistryError(f"{item_path}: invalid example errors {errors!r}, expected only {expected_error!r}")
        frozen_record = _freeze_json(item["record"])
        if not isinstance(frozen_record, Mapping):
            raise RegistryError(f"{item_path}.record: expected mapping")
        parsed_examples.append(
            ExampleIR(
                example_id,
                item["valid"],
                signal,
                description,
                family,
                frozen_record,
                expected_error,
                field_classes,
                base_example,
                mutation_ir,
                builder_context,
            )
        )
        raw_vector: dict[str, Any] = {"signal": signal, "record": copy.deepcopy(item["record"])}
        if family is not None:
            raw_vector["family"] = family
        raw_vectors[example_id] = raw_vector
        validity_by_id[example_id] = item["valid"]
        builder_contexts_by_id[example_id] = builder_context
    return tuple(parsed_examples), InputDigest(normalized, _sha256(raw))


def _parse_metric_settings(
    defaults: Any,
    profiles: Any,
) -> tuple[int, MetricCompatibilityProfileIR]:
    if not isinstance(defaults, dict):
        raise RegistryError("registry.metric_defaults: expected mapping")
    _exact_keys(defaults, {"cardinality_limit"}, set(), "registry.metric_defaults")
    cardinality_limit = _integer(
        defaults["cardinality_limit"],
        "registry.metric_defaults.cardinality_limit",
    )
    if cardinality_limit != EXPECTED_METRIC_CARDINALITY_LIMIT:
        raise RegistryError("registry.metric_defaults.cardinality_limit: expected 2048")
    if not isinstance(profiles, list) or len(profiles) != 1 or not isinstance(profiles[0], dict):
        raise RegistryError("registry.metric_compatibility_profiles: expected one profile")
    profile = profiles[0]
    _exact_keys(
        profile,
        {"id", "high_cardinality_families", "derived_spanmetrics"},
        set(),
        "registry.metric_compatibility_profiles[0]",
    )
    if profile["id"] != "local-observability-v1":
        raise RegistryError("registry.metric_compatibility_profiles[0].id: unexpected profile")
    families = profile["high_cardinality_families"]
    if not isinstance(families, list):
        raise RegistryError("registry.metric_compatibility_profiles[0].high_cardinality_families: expected sequence")
    observed: dict[str, tuple[str, ...]] = {}
    for index, item in enumerate(families):
        item_path = f"registry.metric_compatibility_profiles[0].high_cardinality_families[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(item, {"family", "labels"}, set(), item_path)
        family = _string(item["family"], f"{item_path}.family", pattern=_ID)
        labels = _string_list(item["labels"], f"{item_path}.labels", allow_empty=False)
        if family in observed:
            raise RegistryError(f"{item_path}.family: duplicate family")
        observed[family] = labels
    if len(observed) != 8:
        raise RegistryError(
            "registry.metric_compatibility_profiles[0].high_cardinality_families: "
            "expected the eight reviewed application families"
        )
    spanmetrics = profile["derived_spanmetrics"]
    if not isinstance(spanmetrics, dict):
        raise RegistryError("registry.metric_compatibility_profiles[0].derived_spanmetrics: expected mapping")
    _exact_keys(
        spanmetrics,
        {
            "pipeline",
            "dimensions_cache_size",
            "resource_metrics_cache_size",
            "series_expiration",
        },
        set(),
        "registry.metric_compatibility_profiles[0].derived_spanmetrics",
    )
    expected_spanmetrics = {"pipeline": "spanmetrics/agent360", **EXPECTED_METRIC_PROFILE_LIMITS}
    if spanmetrics != expected_spanmetrics:
        raise RegistryError(
            "registry.metric_compatibility_profiles[0].derived_spanmetrics: must preserve the pinned Collector limits"
        )
    return (
        cardinality_limit,
        MetricCompatibilityProfileIR(
            "local-observability-v1",
            MappingProxyType(dict(observed)),
            DerivedSpanmetricsIR(
                spanmetrics["pipeline"],
                spanmetrics["dimensions_cache_size"],
                spanmetrics["resource_metrics_cache_size"],
                spanmetrics["series_expiration"],
            ),
        ),
    )


def _validate_condition_references(
    groups: Mapping[str, GroupIR],
    conditions: tuple[ConditionIR, ...],
    local_attributes: Mapping[str, AttributeIR],
    upstream_attributes: Mapping[str, tuple[str, SnapshotAttribute]],
) -> None:
    known = {condition.id: condition for condition in conditions}
    for group in groups.values():
        resolved = {use.ref: use for use in group.resolved_uses}
        for use in group.resolved_uses:
            if use.conditional is None:
                continue
            condition = known.get(use.conditional or "")
            if condition is None:
                raise RegistryError(f"group {group.id}: unknown condition ID {use.conditional!r} for {use.ref}")
            if condition.enforcement.kind != "boolean_attribute":
                continue
            source_ref = condition.enforcement.attribute
            if source_ref is None:
                raise RegistryError(f"condition {condition.id}: boolean attribute source is missing")
            source_use = resolved.get(source_ref)
            if (
                source_use is None
                or source_use.requirement_level not in {"required", "recommended", "optional"}
                or source_use.conditional is not None
            ):
                raise RegistryError(
                    f"group {group.id}: condition {condition.id} requires unconditional boolean source {source_ref}"
                )
            local = local_attributes.get(source_ref)
            upstream = upstream_attributes.get(source_ref)
            if (local is None or local.field_type != "boolean") and (
                upstream is None or upstream[1].allowed_types != ("boolean",)
            ):
                raise RegistryError(f"condition {condition.id}: source {source_ref} must be a boolean attribute")


def _validate_value_catalog_attributes(
    catalogs: tuple[ValueCatalogIR, ...],
    local_attributes: Mapping[str, AttributeIR],
) -> None:
    for catalog in catalogs:
        code_attribute = local_attributes.get(catalog.code_attribute)
        value_attributes = [local_attributes.get(reference) for reference in catalog.value_attributes]
        if any(attribute is None for attribute in value_attributes) or code_attribute is None:
            raise RegistryError(f"value catalog {catalog.id}: unknown attribute reference")
        if any(attribute.field_type != "string" for attribute in value_attributes if attribute is not None) or (
            code_attribute.field_type != "int64"
        ):
            raise RegistryError(f"value catalog {catalog.id}: attribute type mismatch")
        values = tuple(entry.value for entry in catalog.entries)
        codes = tuple(entry.code for entry in catalog.entries)
        for reference, value_attribute in zip(catalog.value_attributes, value_attributes, strict=True):
            assert value_attribute is not None
            if (
                value_attribute.normalization.id != "enum-v1"
                or value_attribute.normalization.effective_constraints.get("enum") != values
            ):
                raise RegistryError(
                    f"value catalog {catalog.id}: value attribute {reference} must use the exact catalog enum"
                )
        code_constraints = code_attribute.normalization.effective_constraints
        if (
            code_attribute.normalization.id != "numeric-range-v1"
            or code_constraints.get("min") != min(codes)
            or code_constraints.get("max") != max(codes)
        ):
            raise RegistryError(f"value catalog {catalog.id}: code attribute must use the exact catalog range")


def _structural_field(object_ir: StructuralObjectIR, field_id: str) -> StructuralFieldIR:
    for field in object_ir.fields:
        if field.name == field_id:
            return field
    raise RegistryError(f"structural contract {object_ir.id}: missing field {field_id}")


def _validate_structural_contract_bindings(
    contract: StructuralContractIR,
    envelope_schema_version: int,
    bucket_catalog_version: int,
    semantic_profiles: tuple[SemanticProfileIR, ...],
    groups: Mapping[str, GroupIR],
    local_attributes: Mapping[str, AttributeIR],
    upstream_attributes: Mapping[str, tuple[str, SnapshotAttribute]],
) -> None:
    structural_objects = (
        contract.envelope,
        contract.correlation,
        contract.provenance,
        contract.provenance_import,
        contract.trace_body,
        contract.trace_resource,
        contract.trace_scope,
        contract.trace_status,
        contract.trace_event,
        contract.trace_link,
        contract.metric_instrument_data,
    )
    observed_pseudo_refs: dict[str, tuple[str, str]] = {}
    for object_ir in structural_objects:
        for field in object_ir.fields:
            if field.semantic_ref is None:
                continue
            if field.semantic_ref in PSEUDO_SEMANTIC_REFS:
                expected_placement = PSEUDO_SEMANTIC_REF_PLACEMENTS.get(field.semantic_ref)
                placement = (object_ir.id, field.name)
                if expected_placement != placement:
                    raise RegistryError(
                        f"structural contract {object_ir.id}.{field.name}: pseudo semantic_ref placement mismatch"
                    )
                if field.semantic_ref in observed_pseudo_refs:
                    raise RegistryError(f"structural contract: duplicate pseudo semantic_ref {field.semantic_ref}")
                observed_pseudo_refs[field.semantic_ref] = placement
                continue
            attribute = local_attributes.get(field.semantic_ref)
            if attribute is not None:
                if (
                    field.field_type != attribute.field_type
                    or field.field_class != attribute.field_class
                    or field.sensitivity != attribute.sensitivity
                    or field.normalization is None
                    or field.normalization.id != attribute.normalization.id
                    or field.normalization.effective_constraints != attribute.normalization.effective_constraints
                ):
                    raise RegistryError(f"structural contract {object_ir.id}.{field.name}: semantic attribute mismatch")
                continue
            group = groups.get(field.semantic_ref)
            if group is None:
                raise RegistryError(
                    f"structural contract {object_ir.id}.{field.name}: unknown semantic_ref {field.semantic_ref}"
                )
            if field.field_type != "canonical_json" or group.type not in {"attribute_group", "resource"}:
                raise RegistryError(f"structural contract {object_ir.id}.{field.name}: semantic group type mismatch")
    missing_pseudo_refs = sorted(PSEUDO_SEMANTIC_REFS - observed_pseudo_refs.keys())
    if missing_pseudo_refs:
        raise RegistryError(f"structural contract: missing pseudo semantic_ref values {missing_pseudo_refs}")
    derivation_source_types = {
        "envelope.bucket": _structural_field(contract.envelope, "bucket").field_type,
        "envelope.source": _structural_field(contract.envelope, "source").field_type,
        "envelope.outcome": _structural_field(contract.envelope, "outcome").field_type,
        "family.id": "string",
        "family.family_schema_version": "uint32",
        "provenance.config_generation": _structural_field(contract.provenance, "config_generation").field_type,
        "provenance.binary_version": _structural_field(contract.provenance, "binary_version").field_type,
        "semantic_profile.trace_schema_version": "string",
        "semantic_profile.id": "string",
        "link.relation": "string",
    }
    for derivation in contract.trace_derivations:
        if derivation.target_attribute is not None:
            local_target = local_attributes.get(derivation.target_attribute)
            upstream_target = upstream_attributes.get(derivation.target_attribute)
            if local_target is not None and not local_target.projection_only:
                target_types = (local_target.field_type,)
            elif upstream_target is not None:
                target_types = upstream_target[1].allowed_types
            else:
                raise RegistryError(
                    f"structural contract trace derivation {derivation.id}: target attribute is unavailable"
                )
        elif derivation.target_field == "trace_scope.version":
            target_types = (_structural_field(contract.trace_scope, "version").field_type,)
        else:
            raise RegistryError(f"structural contract trace derivation {derivation.id}: target field is unavailable")
        if target_types != (derivation_source_types[derivation.source],):
            raise RegistryError(f"structural contract trace derivation {derivation.id}: source/target type mismatch")
    schema_field = _structural_field(contract.envelope, "schema_version")
    bucket_version_field = _structural_field(contract.envelope, "bucket_catalog_version")
    if (
        not schema_field.const_present
        or schema_field.const != envelope_schema_version
        or schema_field.normalization is None
        or schema_field.normalization.effective_constraints
        != MappingProxyType({"min": envelope_schema_version, "max": envelope_schema_version})
    ):
        raise RegistryError("structural contract: envelope schema_version binding mismatch")
    if (
        not bucket_version_field.const_present
        or bucket_version_field.const != bucket_catalog_version
        or bucket_version_field.normalization is None
        or bucket_version_field.normalization.effective_constraints
        != MappingProxyType({"min": bucket_catalog_version, "max": bucket_catalog_version})
    ):
        raise RegistryError("structural contract: bucket_catalog_version binding mismatch")
    bucket_attribute = local_attributes.get("defenseclaw.bucket")
    if bucket_attribute is None:
        raise RegistryError("structural contract: defenseclaw.bucket attribute is missing")
    bucket_enum = _structural_field(contract.envelope, "bucket").normalization.effective_constraints.get("enum")
    if bucket_enum != bucket_attribute.normalization.effective_constraints.get("enum"):
        raise RegistryError("structural contract: bucket vocabulary mismatch")
    signal_enum = _structural_field(contract.envelope, "signal").normalization.effective_constraints.get("enum")
    if signal_enum != ("logs", "traces", "metrics"):
        raise RegistryError("structural contract: signal vocabulary mismatch")
    if len(semantic_profiles) != 1:
        raise RegistryError("structural contract: expected one semantic profile")
    profile = semantic_profiles[0]
    if profile.trace_schema_version != "defenseclaw-trace-v1":
        raise RegistryError("structural contract: trace schema profile mismatch")
    scope_name = _structural_field(contract.trace_scope, "name")
    if not scope_name.const_present or scope_name.const != "defenseclaw.telemetry":
        raise RegistryError("structural contract: instrumentation-scope name mismatch")
    scope_schema_url = _structural_field(contract.trace_scope, "schema_url")
    if not scope_schema_url.const_present or scope_schema_url.const != TRACE_SCOPE_SCHEMA_URL:
        raise RegistryError("structural contract: instrumentation-scope schema URL mismatch")
    if _structural_field(contract.trace_resource, "schema_url").const_present:
        raise RegistryError("structural contract: resource schema URL must remain producer input")
    for group_id, group_type in (
        ("resource.core", "resource"),
        ("scope.core", "attribute_group"),
        ("link.core", "attribute_group"),
    ):
        group = groups.get(group_id)
        if group is None or group.type != group_type:
            raise RegistryError(f"structural contract: {group_id} group is missing")
    correlation_fields = {field.name for field in contract.correlation.fields}
    arms_by_signal = {arm.signal: arm for arm in contract.signal_arms}
    trace_arm = arms_by_signal.get("traces")
    if trace_arm is None or trace_arm.required_correlation_fields != ("trace_id", "span_id"):
        raise RegistryError("structural contract: traces require trace_id and span_id correlation")
    if any(
        field not in correlation_fields for arm in contract.signal_arms for field in arm.required_correlation_fields
    ):
        raise RegistryError("structural contract: signal arm references unknown correlation field")
    if any(arm.required_correlation_fields for signal, arm in arms_by_signal.items() if signal != "traces"):
        raise RegistryError("structural contract: only traces require correlation identity")
    semantic_format_contract = {
        "otel-trace-id-v1": (32, "^[0-9a-f]{32}$"),
        "otel-span-id-v1": (16, "^[0-9a-f]{16}$"),
    }
    for object_ir in structural_objects:
        for field in object_ir.fields:
            if field.semantic_format is None:
                continue
            if field.semantic_format == "w3c-tracestate-v1":
                constraints = field.normalization.effective_constraints if field.normalization is not None else {}
                if (
                    field.field_type != "string"
                    or field.normalization is None
                    or field.normalization.id != "bounded-v1"
                    or constraints.get("max_utf8_bytes") != 512
                    or "pattern" in constraints
                ):
                    raise RegistryError(f"structural contract {object_ir.id}.{field.name}: semantic-format mismatch")
                continue
            expected_max, expected_pattern = semantic_format_contract[field.semantic_format]
            constraints = field.normalization.effective_constraints if field.normalization is not None else {}
            if (
                field.field_type != "string"
                or field.normalization is None
                or field.normalization.id != "digest-v1"
                or constraints.get("max_utf8_bytes") != expected_max
                or constraints.get("pattern") != expected_pattern
            ):
                raise RegistryError(f"structural contract {object_ir.id}.{field.name}: semantic-format mismatch")


def _validate_trace_derivation_coverage(
    contract: StructuralContractIR,
    groups: Mapping[str, GroupIR],
) -> None:
    span_unconditional_targets = (
        "defenseclaw.bucket",
        "defenseclaw.span.family",
        "defenseclaw.span.family_schema_version",
        "defenseclaw.source",
        "defenseclaw.config.generation",
    )
    unconditional_attribute_targets = tuple(
        derivation.target_attribute
        for derivation in contract.trace_derivations
        if derivation.target_attribute is not None and derivation.presence == "when-registered"
    )
    source_present_targets = tuple(
        derivation.target_attribute
        for derivation in contract.trace_derivations
        if derivation.target_attribute is not None and derivation.presence == "when-registered-and-source-present"
    )
    if not set(span_unconditional_targets).issubset(unconditional_attribute_targets) or source_present_targets != (
        "defenseclaw.outcome",
    ):
        raise RegistryError("structural contract: trace derivation presence inventory mismatch")

    for group in groups.values():
        if group.type != "span":
            continue
        resolved = {use.ref: use for use in group.resolved_uses}
        for target in span_unconditional_targets:
            use = resolved.get(target)
            if (
                use is None
                or use.role != "attributes"
                or use.requirement_level != "required"
                or use.conditional is not None
            ):
                raise RegistryError(
                    f"group {group.id}: trace derivation target {target} must resolve as an unconditional "
                    "required attribute"
                )

        outcome = resolved.get(source_present_targets[0])
        if group.outcome_requirement == "forbidden":
            if outcome is not None:
                raise RegistryError(
                    f"group {group.id}: forbidden outcome cannot resolve trace derivation target defenseclaw.outcome"
                )
            continue
        if (
            outcome is None
            or outcome.role != "attributes"
            or outcome.requirement_level != "conditional"
            or outcome.conditional != TRACE_OUTCOME_PRESENCE_CONDITION
        ):
            raise RegistryError(
                f"group {group.id}: trace derivation target defenseclaw.outcome must resolve with exact "
                f"{TRACE_OUTCOME_PRESENCE_CONDITION} source-presence semantics"
            )

    required_context_targets = (
        ("resource.core", "resource", "service.version"),
        ("scope.core", "attribute_group", "defenseclaw.trace.schema_version"),
        ("scope.core", "attribute_group", "defenseclaw.semantic_profile"),
        ("link.core", "attribute_group", "defenseclaw.link.relation"),
    )
    for group_id, group_type, target in required_context_targets:
        group = groups.get(group_id)
        if group is None or group.type != group_type:
            raise RegistryError(f"structural contract: trace derivation context {group_id} is unavailable")
        use = next((item for item in group.resolved_uses if item.ref == target), None)
        if (
            use is None
            or use.role != "attributes"
            or use.requirement_level != "required"
            or use.conditional is not None
        ):
            raise RegistryError(
                f"group {group_id}: trace derivation target {target} must resolve as an unconditional "
                "required attribute"
            )

    scope_version = _structural_field(contract.trace_scope, "version")
    if not scope_version.required or scope_version.const_present:
        raise RegistryError("structural contract trace_scope.version: derived target must be required and non-constant")


def _lifecycle_registry_version(value: str, path: str) -> int:
    match = re.fullmatch(r"telemetry-registry-v([1-9][0-9]*)", value)
    if match is None:
        raise RegistryError(f"{path}: expected telemetry-registry-vN")
    return int(match.group(1))


def _parse_go_symbol_contract(
    policy_value: Any,
    overrides_value: Any,
) -> tuple[GoSymbolPolicyIR, tuple[GoSymbolOverrideIR, ...]]:
    path = "registry.go_symbol_policy"
    if not isinstance(policy_value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(
        policy_value,
        {
            "version",
            "package",
            "separators",
            "brand_spellings",
            "initialisms",
            "reserved_word_policy",
            "collision_policy",
            "auto_suffix_policy",
        },
        set(),
        path,
    )
    version = _integer(policy_value["version"], f"{path}.version")
    package = _string(policy_value["package"], f"{path}.package", pattern=_GO_IDENTIFIER)
    separators = _string_list(policy_value["separators"], f"{path}.separators", allow_empty=False)
    brands_raw = policy_value["brand_spellings"]
    if not isinstance(brands_raw, dict):
        raise RegistryError(f"{path}.brand_spellings: expected mapping")
    brands: dict[str, str] = {}
    for key, value in brands_raw.items():
        if not re.fullmatch(r"[a-z][a-z0-9]*", key):
            raise RegistryError(f"{path}.brand_spellings: invalid lowercase brand token")
        spelling = _string(value, f"{path}.brand_spellings.{key}", pattern=_GO_IDENTIFIER)
        brands[key] = spelling
    initialisms = _string_list(policy_value["initialisms"], f"{path}.initialisms", allow_empty=False)
    for index, initialism in enumerate(initialisms):
        if not re.fullmatch(r"[A-Z][A-Z0-9]*", initialism):
            raise RegistryError(f"{path}.initialisms[{index}]: expected uppercase ASCII token")
    parsed = {
        "version": version,
        "package": package,
        "separators": separators,
        "brand_spellings": brands,
        "initialisms": initialisms,
        "reserved_word_policy": _string(policy_value["reserved_word_policy"], f"{path}.reserved_word_policy"),
        "collision_policy": _string(policy_value["collision_policy"], f"{path}.collision_policy"),
        "auto_suffix_policy": _string(policy_value["auto_suffix_policy"], f"{path}.auto_suffix_policy"),
    }
    if parsed != EXPECTED_GO_SYMBOL_POLICY:
        raise RegistryError(f"{path}: policy does not match the exact version 1 contract")
    policy = GoSymbolPolicyIR(
        version,
        package,
        separators,
        _freeze_mapping(brands),
        initialisms,
        parsed["reserved_word_policy"],
        parsed["collision_policy"],
        parsed["auto_suffix_policy"],
    )

    if overrides_value is None:
        return policy, ()
    if not isinstance(overrides_value, list):
        raise RegistryError("registry.go_symbol_overrides: expected sequence")
    overrides: list[GoSymbolOverrideIR] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(overrides_value):
        item_path = f"registry.go_symbol_overrides[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(item, {"kind", "source_id", "symbol", "reason"}, set(), item_path)
        kind = _string(item["kind"], f"{item_path}.kind")
        if kind not in GO_SYMBOL_KIND_ORDER:
            raise RegistryError(f"{item_path}.kind: unknown Go symbol kind")
        source_id = _string(item["source_id"], f"{item_path}.source_id", pattern=_GO_SOURCE_ID)
        _validate_go_override_source_id(policy, kind, source_id, f"{item_path}.source_id")
        symbol = _string(item["symbol"], f"{item_path}.symbol", pattern=_GO_IDENTIFIER)
        reason = _string(item["reason"], f"{item_path}.reason")
        key = (kind, source_id)
        if key in seen:
            raise RegistryError("registry.go_symbol_overrides: duplicate kind/source_id")
        seen.add(key)
        overrides.append(GoSymbolOverrideIR(kind, source_id, symbol, reason))
    return policy, tuple(overrides)


def _validate_go_override_source_id(
    policy: GoSymbolPolicyIR,
    kind: str,
    source_id: str,
    path: str,
) -> None:
    compound_kinds = {
        "structured_member",
        "structured_arm",
        "structured_member_input",
        "structured_member_constructor",
        "span_event_input",
        "span_event_constructor",
        "span_link_input",
        "span_link_constructor",
    }
    parts = source_id.split("#")
    expected_parts = 2 if kind in compound_kinds else 1
    if len(parts) != expected_parts or any(_GO_SOURCE_ID_PART.fullmatch(part) is None for part in parts):
        shape = "owner#member" if expected_parts == 2 else "unscoped identity without #"
        raise RegistryError(f"{path}: expected {shape}")
    for part in parts:
        _go_public_name(policy, part, path)


def _go_public_name(policy: GoSymbolPolicyIR, source: str, path: str) -> str:
    separators = frozenset(policy.separators)
    tokens: list[str] = []
    current: list[str] = []
    for character in source:
        if character in separators:
            if not current:
                raise RegistryError(f"{path}: empty Go symbol token")
            tokens.append("".join(current))
            current = []
            continue
        if not character.isascii() or not character.isalnum():
            raise RegistryError(f"{path}: Go symbol tokens require ASCII letters and digits")
        current.append(character)
    if not current:
        raise RegistryError(f"{path}: empty Go symbol token")
    tokens.append("".join(current))
    brands = policy.brand_spellings
    initialisms = frozenset(policy.initialisms)
    normalized: list[str] = []
    for token in tokens:
        brand = brands.get(token.lower())
        if isinstance(brand, str):
            normalized.append(brand)
        elif token.upper() in initialisms:
            normalized.append(token.upper())
        else:
            normalized.append(token[:1].upper() + token[1:].lower())
    result = "".join(normalized)
    if not result or result[0].isdigit() or _GO_IDENTIFIER.fullmatch(result) is None:
        raise RegistryError(f"{path}: invalid or leading-digit Go symbol result")
    return result


def _go_override_has_required_shape(kind: str, default: str, symbol: str) -> bool:
    fixed_shapes: dict[str, tuple[str, str]] = {
        "attribute": ("TelemetryAttribute", ""),
        "family": ("TelemetryFamily", ""),
        "log_event": ("TelemetryEvent", ""),
        "span_event": ("TelemetrySpanEvent", ""),
        "link_relation": ("TelemetryLinkRelation", ""),
        "metric_instrument": ("TelemetryInstrument", ""),
        "condition": ("TelemetryCondition", ""),
        "condition_fact": ("TelemetryConditionFact", ""),
        "phase": ("TelemetryPhase", ""),
        "phase_code": ("TelemetryPhaseCode", ""),
        "semantic_profile": ("TelemetrySemanticProfile", ""),
        "structured_type": ("TelemetryStructured", ""),
        "structured_member": ("TelemetryStructuredMember", ""),
        "structured_arm": ("TelemetryStructuredArm", ""),
        "structured_member_input": ("", "MemberInput"),
        "structured_member_constructor": ("New", "Member"),
        "resource_attributes_type": ("TelemetryCustomResource", "Attributes"),
        "resource_attributes_constructor": ("NewTelemetryCustomResource", "Attributes"),
        "resource_attributes_attach": ("WithTelemetryCustomResource", "Attributes"),
        "resource_attributes_validator": ("ValidateTelemetryResource", "Attributes"),
        "span_event_input": ("Span", "EventInput"),
        "span_event_constructor": ("NewSpan", "Event"),
        "span_link_input": ("Span", "LinkInput"),
        "span_link_constructor": ("NewSpan", "Link"),
    }
    if kind == "family_input":
        prefix = next((item for item in ("Log", "Span", "Metric") if default.startswith(item)), "")
        suffix = "Input"
    elif kind == "family_builder":
        prefix = next((item for item in ("BuildLog", "BuildSpan", "BuildMetric") if default.startswith(item)), "")
        suffix = ""
    else:
        prefix, suffix = fixed_shapes[kind]
    if not prefix and kind in {"family_input", "family_builder"}:
        return False
    if not default.startswith(prefix) or not symbol.startswith(prefix):
        return False
    if suffix and (not default.endswith(suffix) or not symbol.endswith(suffix)):
        return False
    default_end = len(default) - len(suffix) if suffix else len(default)
    symbol_end = len(symbol) - len(suffix) if suffix else len(symbol)
    default_stem = default[len(prefix) : default_end]
    symbol_stem = symbol[len(prefix) : symbol_end]
    # A reviewed override may only append an ASCII disambiguator to the
    # policy-derived variable stem. This retains the exact signal namespace,
    # suffix, and every policy-owned brand/initialism spelling.
    disambiguator = symbol_stem[len(default_stem) :] if symbol_stem.startswith(default_stem) else ""
    return bool(disambiguator) and disambiguator.isascii() and disambiguator.isalnum()


def _go_symbol_table_digest(rows: tuple[GoSymbolIR, ...]) -> str:
    payload = json.dumps(
        [[row.kind, row.source_id, row.symbol, row.declaration_form] for row in rows],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(b"DefenseClaw GoSymbolTableIR v1\x00" + payload).hexdigest()


def _validate_go_symbol_rows(rows: tuple[GoSymbolIR, ...]) -> None:
    symbol_owners: dict[str, GoSymbolIR] = {}
    for row in rows:
        if _GO_IDENTIFIER.fullmatch(row.symbol) is None or not row.symbol.isascii() or row.symbol[0].isdigit():
            raise RegistryError(f"Go symbol {row.kind}/{row.source_id}: invalid or leading-digit identifier")
        if row.symbol in _GO_RESERVED_IDENTIFIERS:
            raise RegistryError(f"Go symbol {row.kind}/{row.source_id}: reserved identifier collision")
        prior = symbol_owners.get(row.symbol)
        if prior is not None:
            raise RegistryError(f"Go symbol collision: {prior.kind}/{prior.source_id} and {row.kind}/{row.source_id}")
        symbol_owners[row.symbol] = row


def _apply_go_symbol_overrides(
    candidates: tuple[GoSymbolIR, ...],
    overrides: tuple[GoSymbolOverrideIR, ...],
) -> tuple[GoSymbolIR, ...]:
    source_keys = [(row.kind, row.source_id) for row in candidates]
    if len(source_keys) != len(set(source_keys)):
        raise RegistryError("Go symbol table: duplicate kind/source_id")
    defaults_by_symbol: dict[str, list[GoSymbolIR]] = {}
    for row in candidates:
        defaults_by_symbol.setdefault(row.symbol, []).append(row)
    rows_by_key = {(row.kind, row.source_id): row for row in candidates}
    for override in overrides:
        key = (override.kind, override.source_id)
        default = rows_by_key.get(key)
        if default is None:
            raise RegistryError(f"Go symbol override {override.kind}/{override.source_id}: unused override")
        if override.symbol == default.symbol:
            raise RegistryError(f"Go symbol override {override.kind}/{override.source_id}: policy-equivalent override")
        if len(defaults_by_symbol[default.symbol]) < 2:
            raise RegistryError(
                f"Go symbol override {override.kind}/{override.source_id}: no reviewed default collision; "
                "released-symbol preservation requires a future prior-release baseline"
            )
        if not _go_override_has_required_shape(override.kind, default.symbol, override.symbol):
            raise RegistryError(
                f"Go symbol override {override.kind}/{override.source_id}: required namespace shape changed"
            )
        rows_by_key[key] = replace(default, symbol=override.symbol)
    rows = tuple(rows_by_key[key] for key in source_keys)
    _validate_go_symbol_rows(rows)
    return rows


def _build_go_symbol_table(
    policy: GoSymbolPolicyIR,
    overrides: tuple[GoSymbolOverrideIR, ...],
    *,
    domains: tuple[DomainIR, ...],
    upstream_extensions: Mapping[str, AttributeExtensionIR],
    conditions: tuple[ConditionIR, ...],
    value_catalogs: tuple[ValueCatalogIR, ...],
    semantic_profiles: tuple[SemanticProfileIR, ...],
    structured_types: tuple[StructuredTypeIR, ...],
) -> GoSymbolTableIR:
    candidates: list[GoSymbolIR] = []

    def add(kind: str, source_id: str, symbol: str, declaration_form: str) -> None:
        if kind not in GO_SYMBOL_KIND_ORDER:
            raise RegistryError(f"Go symbol {source_id}: internal unknown kind")
        if _GO_SOURCE_ID.fullmatch(source_id) is None:
            raise RegistryError(f"Go symbol {kind}/{source_id}: invalid source identity")
        if _GO_IDENTIFIER.fullmatch(symbol) is None or not symbol.isascii() or symbol[0].isdigit():
            raise RegistryError(f"Go symbol {kind}/{source_id}: invalid exported identifier")
        candidates.append(GoSymbolIR(kind, source_id, symbol, declaration_form))

    local_attributes = [attribute for domain in domains for attribute in domain.attributes]
    attribute_ids = sorted({attribute.id for attribute in local_attributes} | set(upstream_extensions))
    for source_id in attribute_ids:
        add(
            "attribute",
            source_id,
            "TelemetryAttribute" + _go_public_name(policy, source_id, f"Go attribute {source_id}"),
            "exported_const",
        )

    families = sorted(
        (group for domain in domains for group in domain.groups if group.type in _SIGNAL_BY_GROUP_TYPE),
        key=lambda group: group.id.encode("ascii"),
    )
    for group in families:
        family_leading = group.type + "."
        family_source = group.id[len(family_leading) :] if group.id.startswith(family_leading) else group.id
        add(
            "family",
            group.id,
            "TelemetryFamily" + _go_public_name(policy, family_source, f"Go family {group.id}"),
            "exported_const",
        )
    for group in (group for group in families if group.type == "log"):
        if group.event_name is None:
            raise RegistryError(f"Go log event {group.id}: missing event_name")
        add(
            "log_event",
            group.event_name,
            "TelemetryEvent" + _go_public_name(policy, group.event_name, f"Go log event {group.event_name}"),
            "exported_const",
        )

    span_event_groups = sorted(
        (group for domain in domains for group in domain.groups if group.type == "span_event"),
        key=lambda group: group.id.encode("ascii"),
    )
    span_event_names: dict[str, str] = {}
    for group in span_event_groups:
        public_id = group.event_name or (group.id[6:] if group.id.startswith("event.") else group.id)
        span_event_names[group.id] = public_id
        add(
            "span_event",
            public_id,
            "TelemetrySpanEvent" + _go_public_name(policy, public_id, f"Go span event {group.id}"),
            "exported_const",
        )

    link_relations = sorted(
        {relation for group in families if group.type == "span" for relation in (group.link_relations or ())},
        key=str.encode,
    )
    for relation in link_relations:
        add(
            "link_relation",
            relation,
            "TelemetryLinkRelation" + _go_public_name(policy, relation, f"Go link relation {relation}"),
            "exported_const",
        )
    for group in (group for group in families if group.type == "metric"):
        if group.instrument_name is None:
            raise RegistryError(f"Go metric instrument {group.id}: missing instrument_name")
        add(
            "metric_instrument",
            group.instrument_name,
            "TelemetryInstrument"
            + _go_public_name(policy, group.instrument_name, f"Go metric instrument {group.instrument_name}"),
            "exported_const",
        )

    for condition in sorted(conditions, key=lambda item: item.id.encode("ascii")):
        add(
            "condition",
            condition.id,
            "TelemetryCondition" + _go_public_name(policy, condition.id, f"Go condition {condition.id}"),
            "exported_const",
        )
    condition_facts = sorted(
        {
            condition.enforcement.fact
            for condition in conditions
            if condition.enforcement.kind == "builder_fact" and condition.enforcement.fact is not None
        },
        key=str.encode,
    )
    for fact in condition_facts:
        add(
            "condition_fact",
            fact,
            "TelemetryConditionFact" + _go_public_name(policy, fact, f"Go condition fact {fact}"),
            "exported_const",
        )
    phase_entries = tuple(entry for catalog in value_catalogs for entry in catalog.entries)
    for entry in sorted(phase_entries, key=lambda item: item.value.encode("ascii")):
        name = _go_public_name(policy, entry.value, f"Go phase {entry.value}")
        add("phase", entry.value, "TelemetryPhase" + name, "exported_const")
        add("phase_code", entry.value, "TelemetryPhaseCode" + name, "exported_const")
    for profile in sorted(semantic_profiles, key=lambda item: item.id.encode("ascii")):
        add(
            "semantic_profile",
            profile.id,
            "TelemetrySemanticProfile" + _go_public_name(policy, profile.id, f"Go semantic profile {profile.id}"),
            "exported_const",
        )

    ordered_members: list[tuple[str, str]] = []
    for structured_type in structured_types:
        type_name = _go_public_name(policy, structured_type.id, f"Go structured type {structured_type.id}")
        add(
            "structured_type",
            structured_type.id,
            "TelemetryStructured" + type_name,
            "exported_type",
        )
        member_names: list[str] = []
        if structured_type.fields is not None:
            member_names.extend(field.name for field in structured_type.fields)
        if structured_type.discriminator is not None:
            member_names.append(structured_type.discriminator.name)
        dynamic_member_id: str | None = None
        if structured_type.dynamic_members is not None:
            dynamic_member_id = structured_type.dynamic_members.member_id
        elif structured_type.canonical_json is not None:
            dynamic_member_id = structured_type.canonical_json.object_member_id
        if dynamic_member_id is not None:
            member_names.append(dynamic_member_id)
            ordered_members.append((structured_type.id, dynamic_member_id))
        for member_name in member_names:
            source_id = f"{structured_type.id}#{member_name}"
            add(
                "structured_member",
                source_id,
                "TelemetryStructuredMember"
                + type_name
                + _go_public_name(policy, member_name, f"Go structured member {source_id}"),
                "exported_const",
            )
        arm_names: list[str] = []
        if structured_type.canonical_json is not None:
            arm_names.extend(structured_type.canonical_json.arms)
        if structured_type.variants is not None:
            arm_names.extend(variant.tag for variant in structured_type.variants)
        if structured_type.dynamic_variant is not None:
            arm_names.append(structured_type.dynamic_variant.arm_id)
        for arm_name in arm_names:
            source_id = f"{structured_type.id}#{arm_name}"
            add(
                "structured_arm",
                source_id,
                "TelemetryStructuredArm"
                + type_name
                + _go_public_name(policy, arm_name, f"Go structured arm {source_id}"),
                "exported_type",
            )
    for type_id, member_id in ordered_members:
        source_id = f"{type_id}#{member_id}"
        type_name = _go_public_name(policy, type_id, f"Go structured member input {source_id}")
        member_name = _go_public_name(policy, member_id, f"Go structured member input {source_id}")
        add(
            "structured_member_input",
            source_id,
            type_name + member_name + "MemberInput",
            "exported_type",
        )
        add(
            "structured_member_constructor",
            source_id,
            "New" + type_name + member_name + "Member",
            "exported_function",
        )

    add(
        "resource_attributes_type",
        "resource.core",
        "TelemetryCustomResourceAttributes",
        "exported_type",
    )
    add(
        "resource_attributes_constructor",
        "resource.core",
        "NewTelemetryCustomResourceAttributes",
        "exported_function",
    )
    add(
        "resource_attributes_attach",
        "resource.core",
        "WithTelemetryCustomResourceAttributes",
        "exported_function",
    )
    add(
        "resource_attributes_validator",
        "resource.core",
        "ValidateTelemetryResourceAttributes",
        "exported_function",
    )

    for group in families:
        signal_name = {"log": "Log", "span": "Span", "metric": "Metric"}[group.type]
        leading = group.type + "."
        family_source = group.id[len(leading) :] if group.id.startswith(leading) else group.id
        family_name = _go_public_name(policy, family_source, f"Go family API {group.id}")
        add("family_input", group.id, signal_name + family_name + "Input", "exported_type")
        add("family_builder", group.id, "Build" + signal_name + family_name, "family_builder_method")
        if group.type != "span":
            continue
        for event_ref in group.event_refs or ():
            event_group_id = f"event.{event_ref}"
            event_name_id = span_event_names.get(event_group_id)
            if event_name_id is None:
                raise RegistryError(f"Go span event pair {group.id}#{event_ref}: unknown event")
            source_id = f"{group.id}#{event_ref}"
            event_name = _go_public_name(policy, event_name_id, f"Go span event pair {source_id}")
            add(
                "span_event_input",
                source_id,
                "Span" + family_name + event_name + "EventInput",
                "exported_type",
            )
            add(
                "span_event_constructor",
                source_id,
                "NewSpan" + family_name + event_name + "Event",
                "exported_function",
            )
        for relation in group.link_relations or ():
            source_id = f"{group.id}#{relation}"
            relation_name = _go_public_name(policy, relation, f"Go span link pair {source_id}")
            add(
                "span_link_input",
                source_id,
                "Span" + family_name + relation_name + "LinkInput",
                "exported_type",
            )
            add(
                "span_link_constructor",
                source_id,
                "NewSpan" + family_name + relation_name + "Link",
                "exported_function",
            )

    rank = {kind: index for index, kind in enumerate(GO_SYMBOL_KIND_ORDER)}
    candidates.sort(key=lambda row: (rank[row.kind], row.source_id.encode("ascii")))
    rows = _apply_go_symbol_overrides(tuple(candidates), overrides)
    kind_counts = {kind: 0 for kind in GO_SYMBOL_KIND_ORDER}
    declaration_counts = {key: 0 for key in GO_SYMBOL_DECLARATION_FORMS}
    for row in rows:
        kind_counts[row.kind] += 1
        if row.declaration_form not in declaration_counts:
            raise RegistryError(f"Go symbol {row.kind}/{row.source_id}: unknown declaration form")
        declaration_counts[row.declaration_form] += 1
    return GoSymbolTableIR(
        1,
        policy.package,
        rows,
        _freeze_mapping(kind_counts),
        _freeze_mapping(declaration_counts),
        _go_symbol_table_digest(rows),
    )


_CANONICAL_SET_TUPLE_FIELDS: Final = frozenset(
    {
        ("GroupIR", "compatibility_profiles"),
        ("GroupIR", "event_refs"),
        ("GroupIR", "link_relations"),
        ("GroupIR", "mandatory_floor"),
        ("GroupIR", "span_kinds"),
        ("NormalizerIR", "allowed_overrides"),
        ("ProducerMappingIR", "companion_rules"),
        ("ProducerMappingIR", "mandatory_rules"),
        ("RegistryIR", "legacy_only_upstream_attributes"),
        ("SnapshotAttribute", "allowed_types"),
    }
)


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
        return (
            "object",
            tuple((key, _typed_materialized_node(value[key])) for key in sorted(value)),
        )
    if isinstance(value, tuple):
        return ("array", tuple(_typed_materialized_node(item) for item in value))
    raise RegistryError("materialized registry contains an unsupported value")


def _semantic_digest_projection(value: FrozenJSON) -> FrozenJSON:
    if isinstance(value, Mapping):
        projected = {key: _semantic_digest_projection(item) for key, item in value.items()}
        if projected.get("$type") == "NormalizationIR" and isinstance(projected.get("fields"), Mapping):
            fields = dict(projected["fields"])
            fields["notes"] = None
            projected["fields"] = fields
        return MappingProxyType(projected)
    if isinstance(value, tuple):
        return tuple(_semantic_digest_projection(item) for item in value)
    return value


def _materialized_sort_key(value: FrozenJSON) -> bytes:
    return _canonical_json_bytes(_typed_materialized_node(value))


def _materialize_registry_fact(
    value: Any,
    path: tuple[str, ...] = (),
    *,
    tuple_is_set: bool = False,
) -> FrozenJSON:
    if is_dataclass(value) and not isinstance(value, type):
        type_name = type(value).__name__
        materialized_fields = {
            field.name: _materialize_registry_fact(
                getattr(value, field.name),
                (*path, type_name, field.name),
                tuple_is_set=(type_name, field.name) in _CANONICAL_SET_TUPLE_FIELDS,
            )
            for field in dataclass_fields(value)
        }
        return MappingProxyType(
            {
                "$type": type_name,
                "fields": MappingProxyType({key: materialized_fields[key] for key in sorted(materialized_fields)}),
            }
        )
    if isinstance(value, Mapping):
        # Mapping keys remain unrestricted because examples and structured
        # telemetry may legitimately contain "$type" or "fields". Dataclass
        # tags are position-disjoint: only schema-known dataclass positions are
        # interpreted as the {"$type", "fields"} materialized form.
        if any(not isinstance(key, str) for key in value):
            raise RegistryError("materialized registry mappings require string keys")
        return MappingProxyType({key: _materialize_registry_fact(value[key], (*path, key)) for key in sorted(value)})
    if isinstance(value, tuple):
        items = tuple(_materialize_registry_fact(item, (*path, str(index))) for index, item in enumerate(value))
        if tuple_is_set:
            return tuple(sorted(items, key=_materialized_sort_key))
        return items
    if isinstance(value, frozenset):
        return tuple(
            sorted(
                (_materialize_registry_fact(item, (*path, "set")) for item in value),
                key=_materialized_sort_key,
            )
        )
    if value is None or type(value) in {bool, int, float, str, bytes}:
        if type(value) is float and not math.isfinite(value):
            raise RegistryError("materialized registry contains a non-finite number")
        return value
    raise RegistryError("materialized registry contains a mutable or unsupported value")


def _build_materialized_registry_view(registry_values: Mapping[str, Any]) -> MaterializedRegistryView:
    expected_fields = {field.name for field in dataclass_fields(RegistryIR) if field.name != "materialized_view"}
    if set(registry_values) != expected_fields:
        raise RegistryError("materialized registry input does not cover RegistryIR exactly")
    facts = MappingProxyType(
        {
            "$type": "RegistryIR",
            "fields": MappingProxyType(
                {
                    key: _materialize_registry_fact(registry_values[key], ("RegistryIR", key))
                    for key in sorted(registry_values)
                }
            ),
        }
    )
    typed_canonical_json = _canonical_json_bytes(_typed_materialized_node(facts))
    digest = hashlib.sha256(MATERIALIZED_VIEW_DIGEST_DOMAIN + typed_canonical_json).hexdigest()
    return MaterializedRegistryView(
        MATERIALIZED_VIEW_FORMAT,
        facts,
        digest,
    )


_INBOUND_ALIAS_IDS: Final = (
    "conversation-id-v1",
    "codex-conversation-id-v1",
    "request-id-v1",
    "turn-id-v1",
    "codex-turn-id-v1",
    "claudecode-turn-id-v1",
    "provider-v1",
    "request-model-v1",
    "codex-tool-name-v1",
    "codex-tool-call-id-v1",
    "codex-tool-arguments-v1",
    "codex-tool-result-v1",
    "input-content-v1",
    "output-content-v1",
    "input-tokens-v1",
    "output-tokens-v1",
    "cached-input-tokens-v1",
    "log-duration-seconds-v1",
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
_INBOUND_SOURCE_NORMALIZATIONS: Final = frozenset(_INBOUND_SOURCE_NORMALIZER_IDS)
_INBOUND_TOKEN_TYPES: Final = ("input", "output", "cacheRead", "cacheCreation")
_INBOUND_CUMULATIVE_COMPONENT_IDS: Final = (
    "authenticated_source",
    "resource_service_name",
    "resource_service_instance_id",
    "instrument_name",
    "normalized_model",
    "token_type",
    "normalized_conversation",
)
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
_INBOUND_SIGNALS: Final = frozenset({"logs", "traces", "metrics"})
_INBOUND_MODES: Final = frozenset({"import", "derive", "import_and_derive"})
_INBOUND_DURATION_UNIT_SCALES: Final = (
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
_INBOUND_TOKEN_UNIT_SCALES: Final = (
    ("", 1.0),
    ("{token}", 1.0),
    ("token", 1.0),
    ("tokens", 1.0),
)


def _inbound_mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    return value


def _inbound_sequence(value: Any, path: str, *, allow_empty: bool = False) -> list[Any]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise RegistryError(f"{path}: expected {'possibly empty ' if allow_empty else 'nonempty '}sequence")
    return value


def _inbound_source_normalizers(value: Any, *, path: str) -> tuple[dict[str, Any], ...]:
    normalizers: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw_normalizer in enumerate(_inbound_sequence(value, path)):
        normalizer_path = f"{path}[{index}]"
        item = _inbound_mapping(raw_normalizer, normalizer_path)
        normalizer_id = _string(item.get("id"), f"{normalizer_path}.id", pattern=_ID)
        kind = _string(item.get("kind"), f"{normalizer_path}.kind", pattern=_ID)
        if normalizer_id in seen_ids:
            raise RegistryError(f"{normalizer_path}.id: duplicate source normalizer")
        seen_ids.add(normalizer_id)
        common = {
            "id": normalizer_id,
            "kind": kind,
            "trim": _string(item.get("trim"), f"{normalizer_path}.trim", pattern=_ID),
            "case": _string(item.get("case"), f"{normalizer_path}.case", pattern=_ID),
            "max_utf8_bytes": 0,
            "empty": _string(item.get("empty"), f"{normalizer_path}.empty", pattern=_ID),
            "overflow": "",
            "unmatched": "",
            "pattern": "",
            "values": [],
            "separators": [],
            "prefixes": [],
            "rules": [],
        }
        if kind == "bounded":
            _exact_keys(
                item,
                {"id", "kind", "trim", "case", "max_utf8_bytes", "empty", "overflow"},
                set(),
                normalizer_path,
            )
            common["max_utf8_bytes"] = _integer(item["max_utf8_bytes"], f"{normalizer_path}.max_utf8_bytes")
            common["overflow"] = _string(item["overflow"], f"{normalizer_path}.overflow", pattern=_ID)
        elif kind == "identifier":
            _exact_keys(
                item,
                {"id", "kind", "trim", "case", "max_utf8_bytes", "pattern", "empty", "overflow"},
                set(),
                normalizer_path,
            )
            common["max_utf8_bytes"] = _integer(item["max_utf8_bytes"], f"{normalizer_path}.max_utf8_bytes")
            common["pattern"] = _string(item["pattern"], f"{normalizer_path}.pattern")
            try:
                re.compile(common["pattern"], re.ASCII)
            except re.error as error:
                raise RegistryError(f"{normalizer_path}.pattern: invalid regular expression") from error
            common["overflow"] = _string(item["overflow"], f"{normalizer_path}.overflow", pattern=_ID)
        elif kind == "ordered-exact-contains":
            _exact_keys(
                item,
                {"id", "kind", "trim", "case", "max_utf8_bytes", "empty", "overflow", "unmatched", "rules"},
                set(),
                normalizer_path,
            )
            common["max_utf8_bytes"] = _integer(item["max_utf8_bytes"], f"{normalizer_path}.max_utf8_bytes")
            common["overflow"] = _string(item["overflow"], f"{normalizer_path}.overflow", pattern=_ID)
            common["unmatched"] = _string(item["unmatched"], f"{normalizer_path}.unmatched", pattern=_ID)
            rules: list[dict[str, Any]] = []
            seen_exact: set[str] = set()
            seen_contains: set[str] = set()
            for rule_index, raw_rule in enumerate(_inbound_sequence(item["rules"], f"{normalizer_path}.rules")):
                rule_path = f"{normalizer_path}.rules[{rule_index}]"
                rule = _inbound_mapping(raw_rule, rule_path)
                _exact_keys(rule, {"output", "exact", "contains"}, set(), rule_path)
                exact = _string_list(rule["exact"], f"{rule_path}.exact")
                contains = _string_list(rule["contains"], f"{rule_path}.contains")
                if len(exact) != len(set(exact)) or len(contains) != len(set(contains)):
                    raise RegistryError(f"{rule_path}: duplicate normalizer matcher")
                if seen_exact.intersection(exact) or seen_contains.intersection(contains):
                    raise RegistryError(f"{rule_path}: colliding normalizer matcher")
                seen_exact.update(exact)
                seen_contains.update(contains)
                rules.append(
                    {
                        "output": _string(rule["output"], f"{rule_path}.output", pattern=_ID),
                        "exact": list(exact),
                        "contains": list(contains),
                        "inputs": [],
                    }
                )
            common["rules"] = rules
        elif kind == "ordered-prefix-family":
            _exact_keys(
                item,
                {
                    "id",
                    "kind",
                    "trim",
                    "case",
                    "max_utf8_bytes",
                    "empty",
                    "overflow",
                    "unmatched",
                    "separators",
                    "prefixes",
                },
                set(),
                normalizer_path,
            )
            common["max_utf8_bytes"] = _integer(item["max_utf8_bytes"], f"{normalizer_path}.max_utf8_bytes")
            common["overflow"] = _string(item["overflow"], f"{normalizer_path}.overflow", pattern=_ID)
            common["unmatched"] = _string(item["unmatched"], f"{normalizer_path}.unmatched", pattern=_ID)
            common["separators"] = list(
                _string_list(item["separators"], f"{normalizer_path}.separators", allow_empty=False)
            )
            common["prefixes"] = list(_string_list(item["prefixes"], f"{normalizer_path}.prefixes", allow_empty=False))
            if len(common["separators"]) != len(set(common["separators"])) or len(common["prefixes"]) != len(
                set(common["prefixes"])
            ):
                raise RegistryError(f"{normalizer_path}: duplicate separator or prefix")
        elif kind == "exact-map":
            _exact_keys(item, {"id", "kind", "trim", "case", "empty", "unmatched", "rules"}, set(), normalizer_path)
            common["unmatched"] = _string(item["unmatched"], f"{normalizer_path}.unmatched", pattern=_ID)
            rules = []
            seen_inputs: set[str] = set()
            for rule_index, raw_rule in enumerate(_inbound_sequence(item["rules"], f"{normalizer_path}.rules")):
                rule_path = f"{normalizer_path}.rules[{rule_index}]"
                rule = _inbound_mapping(raw_rule, rule_path)
                _exact_keys(rule, {"output", "inputs"}, set(), rule_path)
                inputs = _string_list(rule["inputs"], f"{rule_path}.inputs", allow_empty=False)
                if len(inputs) != len(set(inputs)) or seen_inputs.intersection(inputs):
                    raise RegistryError(f"{rule_path}.inputs: colliding exact-map input")
                seen_inputs.update(inputs)
                rules.append(
                    {
                        "output": _string(rule["output"], f"{rule_path}.output", pattern=_ID),
                        "exact": [],
                        "contains": [],
                        "inputs": list(inputs),
                    }
                )
            common["rules"] = rules
        elif kind == "enum":
            _exact_keys(item, {"id", "kind", "trim", "case", "values", "empty", "unmatched"}, set(), normalizer_path)
            common["unmatched"] = _string(item["unmatched"], f"{normalizer_path}.unmatched", pattern=_ID)
            common["values"] = list(_string_list(item["values"], f"{normalizer_path}.values", allow_empty=False))
            if len(common["values"]) != len(set(common["values"])):
                raise RegistryError(f"{normalizer_path}.values: duplicate enum value")
        else:
            raise RegistryError(f"{normalizer_path}.kind: unsupported source normalizer")
        if common["trim"] not in {"none", "unicode-space"} or common["case"] not in {"preserve", "lowercase"}:
            raise RegistryError(f"{normalizer_path}: unsupported trim or case policy")
        if (
            common["empty"] not in {"reject", "unknown"}
            or common["overflow"] not in {"", "reject", "other"}
            or common["unmatched"] not in {"", "reject", "other"}
        ):
            raise RegistryError(f"{normalizer_path}: unsupported terminal normalization policy")
        normalizers.append(common)
    if tuple(item["id"] for item in normalizers) != _INBOUND_SOURCE_NORMALIZER_IDS:
        raise RegistryError(f"{path}: canonical source normalizer inventory/order mismatch")
    token_type_normalizer = normalizers[-1]
    if (
        token_type_normalizer["kind"] != "exact-map"
        or [rule["output"] for rule in token_type_normalizer["rules"]] != list(_INBOUND_TOKEN_TYPES)
        or [rule["inputs"] for rule in token_type_normalizer["rules"]]
        != [["input"], ["output"], ["cacheRead", "cached_input"], ["cacheCreation"]]
    ):
        raise RegistryError(f"{path}: token type normalizer vocabulary/order mismatch")
    return tuple(normalizers)


def _inbound_source_groups(value: Any, *, path: str) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    seen_sources: set[tuple[str, str]] = set()
    for index, raw_group in enumerate(_inbound_sequence(value, path)):
        group_path = f"{path}[{index}]"
        group = _inbound_mapping(raw_group, group_path)
        _exact_keys(group, {"placement", "keys"}, set(), group_path)
        placement = _string(group["placement"], f"{group_path}.placement", pattern=_ID)
        if placement not in _INBOUND_SOURCE_PLACEMENTS:
            raise RegistryError(f"{group_path}.placement: unknown source placement")
        keys = _string_list(group["keys"], f"{group_path}.keys", allow_empty=False)
        if len(keys) != len(set(keys)):
            raise RegistryError(f"{group_path}.keys: duplicate source key")
        if placement == "authenticated_source" and keys != ("$authenticated_source",):
            raise RegistryError(f"{group_path}: authenticated source placement has one sealed key")
        if placement == "instrument_name" and keys != ("$instrument_name",):
            raise RegistryError(f"{group_path}: instrument placement has one sealed key")
        if placement in {"metric_point_attribute", "resource_attribute"} and any(
            _ID.fullmatch(key) is None for key in keys
        ):
            raise RegistryError(f"{group_path}.keys: attribute source keys must be stable tokens")
        if placement == "fixed" and len(keys) != 1:
            raise RegistryError(f"{group_path}.keys: fixed placement requires one literal")
        for key in keys:
            identity = (placement, key)
            if identity in seen_sources:
                raise RegistryError(f"{path}: colliding source declaration {placement}/{key}")
            seen_sources.add(identity)
        groups.append({"placement": placement, "keys": list(keys)})
    return groups


def _inbound_source_rule(
    value: Any,
    *,
    path: str,
    identity_key: str,
    include_disposition: bool,
) -> dict[str, Any]:
    rule = _inbound_mapping(value, path)
    required = {identity_key, "requirement", "normalization", "source_groups"}
    optional = {"allowed_values"}
    if include_disposition:
        required.add("disposition")
    _exact_keys(rule, required, optional, path)
    identity = _string(rule[identity_key], f"{path}.{identity_key}", pattern=_ID)
    if include_disposition and rule["disposition"] != "project":
        raise RegistryError(f"{path}.disposition: projected rule requires project")
    requirement = _string(rule["requirement"], f"{path}.requirement", pattern=_ID)
    if requirement not in {"required", "optional"}:
        raise RegistryError(f"{path}.requirement: expected required or optional")
    normalization = _string(rule["normalization"], f"{path}.normalization", pattern=_ID)
    if normalization not in _INBOUND_SOURCE_NORMALIZATIONS:
        raise RegistryError(f"{path}.normalization: unsupported source normalization")
    allowed_values = list(_string_list(rule.get("allowed_values", []), f"{path}.allowed_values"))
    if normalization == "token-type-label-v1":
        if tuple(allowed_values) != _INBOUND_TOKEN_TYPES:
            raise RegistryError(f"{path}.allowed_values: canonical token-type vocabulary/order mismatch")
    elif allowed_values:
        raise RegistryError(f"{path}.allowed_values: only token-type-label-v1 may declare values")
    return {
        identity_key: identity,
        **({"disposition": "project"} if include_disposition else {}),
        "requirement": requirement,
        "normalization": normalization,
        "allowed_values": allowed_values,
        "source_groups": _inbound_source_groups(rule["source_groups"], path=f"{path}.source_groups"),
    }


def _inbound_source_projection_plans(
    value: Any,
    *,
    path: str,
    groups: Mapping[str, GroupIR],
) -> tuple[dict[str, Any], ...]:
    plans: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw_plan in enumerate(_inbound_sequence(value, path)):
        plan_path = f"{path}[{index}]"
        plan = _inbound_mapping(raw_plan, plan_path)
        _exact_keys(plan, {"id", "target_family", "field_rules", "cumulative_series"}, set(), plan_path)
        plan_id = _string(plan["id"], f"{plan_path}.id", pattern=_ID)
        family_id = _string(plan["target_family"], f"{plan_path}.target_family", pattern=_ID)
        if plan_id in seen_ids:
            raise RegistryError(f"{plan_path}.id: duplicate source projection plan")
        seen_ids.add(plan_id)
        family = groups.get(family_id)
        if family is None or family.type != "metric":
            raise RegistryError(f"{plan_path}.target_family: expected metric family")
        field_rules: list[dict[str, Any]] = []
        seen_targets: set[str] = set()
        for rule_index, raw_rule in enumerate(_inbound_sequence(plan["field_rules"], f"{plan_path}.field_rules")):
            rule_path = f"{plan_path}.field_rules[{rule_index}]"
            rule = _inbound_mapping(raw_rule, rule_path)
            target = _string(rule.get("target"), f"{rule_path}.target", pattern=_ID)
            if target in seen_targets:
                raise RegistryError(f"{rule_path}.target: duplicate field disposition")
            seen_targets.add(target)
            disposition = _string(rule.get("disposition"), f"{rule_path}.disposition", pattern=_ID)
            if disposition == "omit":
                _exact_keys(rule, {"target", "disposition"}, set(), rule_path)
                field_rules.append({"target": target, "disposition": "omit"})
            elif disposition == "project":
                field_rules.append(
                    _inbound_source_rule(
                        rule,
                        path=rule_path,
                        identity_key="target",
                        include_disposition=True,
                    )
                )
            else:
                raise RegistryError(f"{rule_path}.disposition: expected project or omit")
        expected_targets = tuple(sorted((use.ref for use in family.resolved_uses), key=str.encode))
        if tuple(rule["target"] for rule in field_rules) != expected_targets:
            raise RegistryError(f"{plan_path}.field_rules: must cover target fields exactly in canonical order")

        cumulative_raw = plan["cumulative_series"]
        cumulative: dict[str, Any] | None = None
        if cumulative_raw is not None:
            cumulative_path = f"{plan_path}.cumulative_series"
            cumulative_map = _inbound_mapping(cumulative_raw, cumulative_path)
            _exact_keys(
                cumulative_map,
                {"applicability", "framing", "normalization_stage", "components", "reset_epoch"},
                set(),
                cumulative_path,
            )
            if (
                cumulative_map["applicability"] != "monotonic-cumulative-sum"
                or cumulative_map["framing"] != "length-prefixed-presence-v1"
                or cumulative_map["normalization_stage"] != "before_framing"
            ):
                raise RegistryError(f"{cumulative_path}: cumulative identity policy drift")
            components: list[dict[str, Any]] = []
            for component_index, raw_component in enumerate(
                _inbound_sequence(cumulative_map["components"], f"{cumulative_path}.components")
            ):
                components.append(
                    _inbound_source_rule(
                        raw_component,
                        path=f"{cumulative_path}.components[{component_index}]",
                        identity_key="id",
                        include_disposition=False,
                    )
                )
            component_ids = tuple(component["id"] for component in components)
            if component_ids != _INBOUND_CUMULATIVE_COMPONENT_IDS or len(component_ids) != len(set(component_ids)):
                raise RegistryError(f"{cumulative_path}.components: canonical series identity/order mismatch")
            reset = _inbound_mapping(cumulative_map["reset_epoch"], f"{cumulative_path}.reset_epoch")
            _exact_keys(
                reset,
                {"role", "identity", "placement", "key", "normalization"},
                set(),
                f"{cumulative_path}.reset_epoch",
            )
            expected_reset = {
                "role": "reset_only",
                "identity": False,
                "placement": "metric_point_start_time",
                "key": "$start_time_unix_nano",
                "normalization": "unsigned-epoch-nanos-v1",
            }
            if reset != expected_reset:
                raise RegistryError(f"{cumulative_path}.reset_epoch: start time is reset metadata only")
            cumulative = {
                "applicability": cumulative_map["applicability"],
                "framing": cumulative_map["framing"],
                "normalization_stage": cumulative_map["normalization_stage"],
                "components": components,
                "reset_epoch": expected_reset,
            }
        plans.append(
            {
                "id": plan_id,
                "target_family": family_id,
                "field_rules": field_rules,
                "cumulative_series": cumulative,
            }
        )
    if tuple(plan["id"] for plan in plans) != _INBOUND_SOURCE_PROJECTION_PLAN_IDS:
        raise RegistryError(f"{path}: canonical source projection inventory/order mismatch")
    if plans[0]["target_family"] != "metric.gen_ai.client.token.usage" or plans[0]["cumulative_series"] is None:
        raise RegistryError(f"{path}: token metric projection/cumulative authority is incomplete")
    if (
        plans[1]["target_family"] != "metric.gen_ai.client.operation.duration"
        or plans[1]["cumulative_series"] is not None
    ):
        raise RegistryError(f"{path}: duration metric projection authority is invalid")
    return tuple(plans)


def _inbound_unit_rule(value: Any, *, strategy: str, path: str) -> dict[str, Any]:
    if strategy == "generated-reverse-metric-v1":
        rule = _inbound_mapping(value, path)
        _exact_keys(rule, {"kind"}, set(), path)
        if rule["kind"] != "target-unit-equality-v1":
            raise RegistryError(f"{path}.kind: reverse metrics require target-unit-equality-v1")
        return {"kind": "target-unit-equality-v1", "accepted": []}
    expected = {
        "duration-metric-v1": _INBOUND_DURATION_UNIT_SCALES,
        "claude-token-usage-v1": _INBOUND_TOKEN_UNIT_SCALES,
    }.get(strategy)
    if expected is None:
        raise RegistryError(f"{path}: unit rule is forbidden for mapping strategy {strategy}")
    rule = _inbound_mapping(value, path)
    _exact_keys(rule, {"kind", "accepted"}, set(), path)
    if rule["kind"] != "scale-table-v1":
        raise RegistryError(f"{path}.kind: scale-table-v1 required")
    accepted: list[dict[str, Any]] = []
    for index, raw_entry in enumerate(_inbound_sequence(rule["accepted"], f"{path}.accepted")):
        entry_path = f"{path}.accepted[{index}]"
        entry = _inbound_mapping(raw_entry, entry_path)
        _exact_keys(entry, {"source_unit", "scale"}, set(), entry_path)
        source_unit = entry["source_unit"]
        if not isinstance(source_unit, str) or len(source_unit.encode("utf-8")) > 64:
            raise RegistryError(f"{entry_path}.source_unit: expected bounded UTF-8 string")
        scale = entry["scale"]
        if type(scale) not in {int, float} or isinstance(scale, bool) or not math.isfinite(float(scale)) or scale <= 0:
            raise RegistryError(f"{entry_path}.scale: expected finite positive number")
        accepted.append({"source_unit": source_unit, "scale": float(scale)})
    observed = tuple((entry["source_unit"], entry["scale"]) for entry in accepted)
    if observed != expected:
        raise RegistryError(f"{path}.accepted: canonical source-unit table/order mismatch")
    return {"kind": "scale-table-v1", "accepted": accepted}


def _resolved_inbound_unit_rule(rule: Mapping[str, Any] | None, *, target: GroupIR, path: str) -> dict[str, Any]:
    if rule is None:
        return {"kind": "none", "target_unit": "", "accepted": []}
    if target.type != "metric" or target.metric_unit is None:
        raise RegistryError(f"{path}: source-unit rule requires a metric target")
    kind = rule["kind"]
    if kind == "target-unit-equality-v1":
        return {
            "kind": kind,
            "target_unit": target.metric_unit,
            "accepted": [{"source_unit": target.metric_unit, "scale": 1.0}],
        }
    expected_target = {"duration-metric-v1": "s", "claude-token-usage-v1": "{token}"}
    if kind != "scale-table-v1" or target.metric_unit != expected_target.get(path):
        raise RegistryError(f"registry.inbound_bindings: {path} target unit disagrees with its sealed metric family")
    return {"kind": kind, "target_unit": target.metric_unit, "accepted": list(rule["accepted"])}


def _inbound_predicates(
    raw: Any,
    *,
    path: str,
    target: GroupIR,
    case: Mapping[str, Any] | None,
    constants: Mapping[str, Any],
) -> tuple[dict[str, Any], ...]:
    predicates: list[dict[str, Any]] = []
    for index, value in enumerate(_inbound_sequence(raw, path)):
        item_path = f"{path}[{index}]"
        item = _inbound_mapping(value, item_path)
        _exact_keys(item, {"location", "key", "operator", "value_type"}, {"values"}, item_path)
        location = _string(item["location"], f"{item_path}.location", pattern=_ID)
        key = _string(item["key"], f"{item_path}.key")
        operator = _string(item["operator"], f"{item_path}.operator", pattern=_ID)
        value_type = _string(item["value_type"], f"{item_path}.value_type", pattern=_ID)
        values = list(item.get("values", ()))
        if key == "$expansion_required_key":
            if case is None:
                raise RegistryError(f"{item_path}.key: expansion key outside case expansion")
            key = _string(case["required_key"], f"{item_path}.key", pattern=_ID)
            value_type = "string"
        if operator == "equals_target_bucket":
            operator, values = "equals", [target.bucket]
        elif operator == "equals_target_event":
            operator, values = "equals", [target.event_name]
        elif operator == "equals_target_family":
            operator, values = "equals", [target.id]
        elif operator == "equals_target_schema_version":
            operator, values = "equals", [target.family_schema_version]
        elif operator == "equals_target_instrument":
            operator, values = "equals", [target.instrument_name]
        elif operator == "equals_expansion_operation":
            if case is None:
                raise RegistryError(f"{item_path}.operator: operation outside case expansion")
            operator, values = "equals", [_string(case["operation"], f"{item_path}.operation", pattern=_ID)]
        elif operator == "equals_expansion_instrument":
            if case is None:
                raise RegistryError(f"{item_path}.operator: instrument outside source-case expansion")
            operator, values = "equals", [_string(case["instrument_name"], f"{item_path}.instrument_name", pattern=_ID)]
        elif operator == "equals_contract":
            contract_key = key.removeprefix("$")
            if contract_key not in constants:
                raise RegistryError(f"{item_path}.key: unknown inbound contract constant")
            operator, values = "equals", [constants[contract_key]]
        elif operator == "reversible_target_shape":
            shapes = {
                "counter": ("sum_delta_monotonic",),
                "gauge": ("gauge",),
                "updowncounter": ("sum_delta",),
            }.get(target.instrument_type or "")
            if shapes is None:
                raise RegistryError(f"{item_path}.operator: target metric shape is not reversible")
            operator, values = "one_of", list(shapes)
        if operator in {"equals", "one_of", "uint32_max"} and not values:
            raise RegistryError(f"{item_path}.values: required for {operator}")
        if operator in {"present", "absent", "projected_record_json", "valid_ended_span"} and values:
            raise RegistryError(f"{item_path}.values: forbidden for {operator}")
        if operator not in {
            "equals",
            "one_of",
            "present",
            "absent",
            "uint32_max",
            "projected_record_json",
            "valid_ended_span",
        }:
            raise RegistryError(f"{item_path}.operator: unsupported inbound predicate")
        predicates.append(
            {
                "location": location,
                "key": key,
                "operator": operator,
                "values": values,
                "value_type": value_type,
            }
        )
    identities = [(item["location"], item["key"]) for item in predicates]
    if len(identities) != len(set(identities)):
        raise RegistryError(f"{path}: duplicate predicate location/key")
    return tuple(predicates)


def _inbound_disjoint(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    if left["shape"] != right["shape"]:
        return True
    left_by_key = {(item["location"], item["key"]): item for item in left["discriminator"]["predicates"]}
    right_by_key = {(item["location"], item["key"]): item for item in right["discriminator"]["predicates"]}
    for identity in set(left_by_key) & set(right_by_key):
        first, second = left_by_key[identity], right_by_key[identity]
        if {first["operator"], second["operator"]} == {"present", "absent"}:
            return True
        if first["operator"] == "absent" and second["operator"] in {"equals", "one_of", "present"}:
            return True
        if second["operator"] == "absent" and first["operator"] in {"equals", "one_of", "present"}:
            return True
        if first["operator"] in {"equals", "one_of"} and second["operator"] in {"equals", "one_of"}:
            if set(first["values"]).isdisjoint(second["values"]):
                return True
    return False


def _parse_inbound_otlp(
    value: Any,
    *,
    groups: Mapping[str, GroupIR],
) -> InboundOTLPIR:
    path = "registry.inbound_bindings"
    source = _inbound_mapping(value, path)
    _exact_keys(
        source,
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
            "alias_sets",
            "source_normalizers",
            "source_projection_plans",
            "binding_classes",
            "derivation_attachments",
            "fixture_policy",
        },
        set(),
        path,
    )
    if _integer(source["version"], f"{path}.version") != 1:
        raise RegistryError(f"{path}.version: unsupported version")
    if _integer(source["max_forward_hops"], f"{path}.max_forward_hops") != 4:
        raise RegistryError(f"{path}.max_forward_hops: must be 4")
    expected_constants = {
        "unknown_fields": "drop_and_count",
        "semantic_resource_instance_key": "defenseclaw.instance.id",
        "forward_instance_key": "defenseclaw.telemetry.forward.instance_id",
        "forward_destination_key": "defenseclaw.telemetry.forward.destination",
        "forward_hop_count_key": "defenseclaw.telemetry.forward.hop_count",
        "record_id_key": "defenseclaw.record.id",
        "scope_name": "defenseclaw.telemetry",
        "scope_schema_url": "https://defenseclaw.io/schemas/telemetry/v8",
        "resource_schema_url": "https://opentelemetry.io/schemas/1.42.0",
    }
    for key, expected in expected_constants.items():
        if _string(source[key], f"{path}.{key}") != expected:
            raise RegistryError(f"{path}.{key}: contract drift")
    constants = {
        "scope_name": expected_constants["scope_name"],
        "scope_schema_url": expected_constants["scope_schema_url"],
        "resource_schema_url": expected_constants["resource_schema_url"],
    }

    alias_sets: list[dict[str, Any]] = []
    aliases_by_id: dict[str, dict[str, Any]] = {}
    for index, raw_alias in enumerate(_inbound_sequence(source["alias_sets"], f"{path}.alias_sets")):
        alias_path = f"{path}.alias_sets[{index}]"
        alias = _inbound_mapping(raw_alias, alias_path)
        _exact_keys(alias, {"id", "target", "value_type", "normalization", "sources"}, set(), alias_path)
        alias_id = _string(alias["id"], f"{alias_path}.id", pattern=_ID)
        target = _string(alias["target"], f"{alias_path}.target")
        sources = _string_list(alias["sources"], f"{alias_path}.sources", allow_empty=False)
        parsed = {
            "id": alias_id,
            "target": target,
            "value_type": _string(alias["value_type"], f"{alias_path}.value_type", pattern=_ID),
            "normalization": _string(alias["normalization"], f"{alias_path}.normalization", pattern=_ID),
            "sources": list(sources),
            "conflict_policy": "reject",
            "absence_policy": "omit",
        }
        if alias_id in aliases_by_id:
            raise RegistryError(f"{alias_path}.id: duplicate alias set")
        aliases_by_id[alias_id] = parsed
        alias_sets.append(parsed)
    if tuple(item["id"] for item in alias_sets) != _INBOUND_ALIAS_IDS:
        raise RegistryError(f"{path}.alias_sets: canonical inventory/order mismatch")

    source_normalizers = _inbound_source_normalizers(
        source["source_normalizers"],
        path=f"{path}.source_normalizers",
    )
    source_projection_plans = _inbound_source_projection_plans(
        source["source_projection_plans"],
        path=f"{path}.source_projection_plans",
        groups=groups,
    )
    source_projection_by_id = {plan["id"]: plan for plan in source_projection_plans}
    referenced_normalizers = {
        rule["normalization"]
        for plan in source_projection_plans
        for rule in (
            [item for item in plan["field_rules"] if item["disposition"] == "project"]
            + ([] if plan["cumulative_series"] is None else plan["cumulative_series"]["components"])
        )
    }
    if referenced_normalizers != set(_INBOUND_SOURCE_NORMALIZER_IDS):
        raise RegistryError(f"{path}.source_normalizers: declarations must all be referenced")
    referenced_source_projection_plans: list[str] = []

    classes: list[dict[str, Any]] = []
    for index, raw_class in enumerate(_inbound_sequence(source["binding_classes"], f"{path}.binding_classes")):
        class_path = f"{path}.binding_classes[{index}]"
        item = _inbound_mapping(raw_class, class_path)
        _exact_keys(
            item,
            {
                "id",
                "signal",
                "sources",
                "mode",
                "expansion",
                "discriminator",
                "mapping",
                "derived_targets",
                "time_rule",
                "outcome_rule",
                "native_round_trip",
            },
            set(),
            class_path,
        )
        class_id = _string(item["id"], f"{class_path}.id", pattern=_ID)
        signal = _string(item["signal"], f"{class_path}.signal", pattern=_ID)
        mode = _string(item["mode"], f"{class_path}.mode", pattern=_ID)
        if signal not in _INBOUND_SIGNALS or mode not in _INBOUND_MODES:
            raise RegistryError(f"{class_path}: invalid signal or mode")
        mapping = _inbound_mapping(item["mapping"], f"{class_path}.mapping")
        _exact_keys(
            mapping,
            {"strategy", "alias_sets"},
            {"unit_rule", "source_projection_plan"},
            f"{class_path}.mapping",
        )
        mapping_strategy = _string(mapping["strategy"], f"{class_path}.mapping.strategy", pattern=_ID)
        raw_unit_rule = mapping.get("unit_rule")
        unit_rule = None
        if raw_unit_rule is not None:
            unit_rule = _inbound_unit_rule(
                raw_unit_rule,
                strategy=mapping_strategy,
                path=f"{class_path}.mapping.unit_rule",
            )
        elif mapping_strategy in {
            "generated-reverse-metric-v1",
            "duration-metric-v1",
            "claude-token-usage-v1",
        }:
            raise RegistryError(f"{class_path}.mapping.unit_rule: required for {mapping_strategy}")
        alias_ids = _string_list(mapping["alias_sets"], f"{class_path}.mapping.alias_sets")
        if any(alias_id not in aliases_by_id for alias_id in alias_ids):
            raise RegistryError(f"{class_path}.mapping.alias_sets: unknown alias set")
        source_projection_plan_id = mapping.get("source_projection_plan")
        if source_projection_plan_id is not None:
            source_projection_plan_id = _string(
                source_projection_plan_id,
                f"{class_path}.mapping.source_projection_plan",
                pattern=_ID,
            )
            if source_projection_plan_id not in source_projection_by_id:
                raise RegistryError(f"{class_path}.mapping.source_projection_plan: unknown plan")
            referenced_source_projection_plans.append(source_projection_plan_id)
        expected_projection_plan = {
            "claude-token-usage-v1": "genai-token-metric-v1",
            "duration-metric-v1": "genai-duration-metric-v1",
        }.get(mapping_strategy)
        if source_projection_plan_id != expected_projection_plan:
            if expected_projection_plan is None:
                raise RegistryError(f"{class_path}.mapping.source_projection_plan: forbidden for {mapping_strategy}")
            raise RegistryError(f"{class_path}.mapping.source_projection_plan: required for {mapping_strategy}")
        if source_projection_plan_id is not None and alias_ids:
            raise RegistryError(f"{class_path}.mapping: source projection plan and alias sets cannot both own fields")
        discriminator = _inbound_mapping(item["discriminator"], f"{class_path}.discriminator")
        _exact_keys(discriminator, {"kind", "predicates"}, set(), f"{class_path}.discriminator")
        derived_targets = _inbound_sequence(item["derived_targets"], f"{class_path}.derived_targets", allow_empty=True)
        for derived_index, raw_target in enumerate(derived_targets):
            target_path = f"{class_path}.derived_targets[{derived_index}]"
            target = _inbound_mapping(raw_target, target_path)
            _exact_keys(target, {"family", "strategy"}, set(), target_path)
            family_id = _string(target["family"], f"{target_path}.family", pattern=_ID)
            if family_id not in groups or groups[family_id].type != "metric":
                raise RegistryError(f"{target_path}.family: expected metric family")
        classes.append(
            {
                "id": class_id,
                "signal": signal,
                "sources": list(_string_list(item["sources"], f"{class_path}.sources", allow_empty=False)),
                "mode": mode,
                "expansion": item["expansion"],
                "discriminator": discriminator,
                "mapping": {
                    "strategy": mapping_strategy,
                    "alias_sets": list(alias_ids),
                    "source_projection_plan": source_projection_plan_id,
                    "unit_rule": unit_rule,
                },
                "derived_targets": derived_targets,
                "time_rule": item["time_rule"],
                "outcome_rule": item["outcome_rule"],
                "native_round_trip": item["native_round_trip"],
            }
        )
    if tuple(item["id"] for item in classes) != _INBOUND_CLASS_IDS:
        raise RegistryError(f"{path}.binding_classes: canonical inventory/order mismatch")
    if tuple(dict.fromkeys(referenced_source_projection_plans)) != _INBOUND_SOURCE_PROJECTION_PLAN_IDS:
        raise RegistryError(f"{path}.source_projection_plans: declarations must each be referenced")

    matches: list[dict[str, Any]] = []
    targets_by_match: dict[str, list[dict[str, Any]]] = {}
    for class_index, item in enumerate(classes):
        class_path = f"{path}.binding_classes[{class_index}]"
        expansion = _inbound_mapping(item["expansion"], f"{class_path}.expansion")
        kind = _string(expansion.get("kind"), f"{class_path}.expansion.kind", pattern=_ID)
        expanded_cases: list[tuple[GroupIR, Mapping[str, Any] | None, str]] = []
        if kind == "all_signal_families":
            _exact_keys(expansion, {"kind"}, set(), f"{class_path}.expansion")
            group_type = {"logs": "log", "traces": "span"}.get(item["signal"])
            if group_type is None:
                raise RegistryError(f"{class_path}.expansion: all families requires logs/traces")
            expanded_cases = [(group, None, group.id) for group in groups.values() if group.type == group_type]
        elif kind == "reversible_metric_families":
            _exact_keys(expansion, {"kind", "instrument_types"}, set(), f"{class_path}.expansion")
            instruments = _string_list(
                expansion["instrument_types"], f"{class_path}.expansion.instrument_types", allow_empty=False
            )
            if instruments != ("counter", "gauge", "updowncounter"):
                raise RegistryError(f"{class_path}.expansion.instrument_types: contract drift")
            expanded_cases = [
                (group, None, group.id)
                for group in groups.values()
                if group.type == "metric" and group.instrument_type in instruments
            ]
        elif kind == "singleton":
            _exact_keys(expansion, {"kind", "primary_family"}, set(), f"{class_path}.expansion")
            family_id = _string(expansion["primary_family"], f"{class_path}.expansion.primary_family", pattern=_ID)
            target = groups.get(family_id)
            if target is None:
                raise RegistryError(f"{class_path}.expansion.primary_family: unknown family")
            expanded_cases = [(target, None, target.id)]
        elif kind == "cases":
            _exact_keys(expansion, {"kind", "cases"}, set(), f"{class_path}.expansion")
            for case_index, raw_case in enumerate(
                _inbound_sequence(expansion["cases"], f"{class_path}.expansion.cases")
            ):
                case_path = f"{class_path}.expansion.cases[{case_index}]"
                case = _inbound_mapping(raw_case, case_path)
                _exact_keys(
                    case,
                    {"id_suffix", "primary_family", "operation", "required_key"},
                    {"target_key", "normalization"},
                    case_path,
                )
                target = groups.get(_string(case["primary_family"], f"{case_path}.primary_family", pattern=_ID))
                if target is None or target.type != "span":
                    raise RegistryError(f"{case_path}.primary_family: expected span family")
                expanded_cases.append((target, case, target.id))
        elif kind == "source_cases":
            _exact_keys(expansion, {"kind", "primary_family", "cases"}, set(), f"{class_path}.expansion")
            family_id = _string(expansion["primary_family"], f"{class_path}.expansion.primary_family", pattern=_ID)
            target = groups.get(family_id)
            if target is None or target.type != "metric":
                raise RegistryError(f"{class_path}.expansion.primary_family: expected metric family")
            for case_index, raw_case in enumerate(
                _inbound_sequence(expansion["cases"], f"{class_path}.expansion.cases")
            ):
                case_path = f"{class_path}.expansion.cases[{case_index}]"
                case = _inbound_mapping(raw_case, case_path)
                _exact_keys(case, {"id_suffix", "instrument_name"}, set(), case_path)
                suffix = _string(case["id_suffix"], f"{case_path}.id_suffix", pattern=_ID)
                _string(case["instrument_name"], f"{case_path}.instrument_name", pattern=_ID)
                expanded_cases.append((target, case, suffix))
        else:
            raise RegistryError(f"{class_path}.expansion.kind: unsupported kind")
        expanded_cases.sort(key=lambda pair: pair[2].encode("ascii"))
        for target, case, variant_id in expanded_cases:
            match_id = f"{item['id']}.{variant_id}"
            source_unit_rule = _resolved_inbound_unit_rule(
                item["mapping"]["unit_rule"],
                target=target,
                path=item["mapping"]["strategy"],
            )
            predicates = _inbound_predicates(
                item["discriminator"]["predicates"],
                path=f"{class_path}.discriminator.predicates",
                target=target,
                case=case,
                constants=constants,
            )
            target_override: dict[str, Any] | None = None
            if case is not None and "target_key" in case:
                target_override = {
                    "source": case["required_key"],
                    "target": case["target_key"],
                    "normalization": case["normalization"],
                }
            shape = "native_exact" if item["native_round_trip"] else "external"
            matches.append(
                {
                    "id": match_id,
                    "class_id": item["id"],
                    "signal": item["signal"],
                    "sources": item["sources"],
                    "shape": shape,
                    "discriminator": {
                        "kind": item["discriminator"]["kind"],
                        "predicates": list(predicates),
                    },
                    "mapping": {
                        "strategy": item["mapping"]["strategy"],
                        "alias_sets": [aliases_by_id[alias_id] for alias_id in item["mapping"]["alias_sets"]],
                        "source_projection_plan": (
                            None
                            if item["mapping"]["source_projection_plan"] is None
                            else source_projection_by_id[item["mapping"]["source_projection_plan"]]
                        ),
                        "target_override": target_override,
                        "source_unit_rule": source_unit_rule,
                    },
                    "derived_targets": item["derived_targets"],
                    "time_rule": item["time_rule"],
                    "outcome_rule": item["outcome_rule"],
                    "unknown_fields": "drop_and_count",
                    "native_round_trip": item["native_round_trip"],
                    "target_ids": [],
                }
            )
            role = "import" if item["mode"] in {"import", "import_and_derive"} else "derive"
            projection_plan_id = item["mapping"]["source_projection_plan"]
            projection_plan = None if projection_plan_id is None else source_projection_by_id[projection_plan_id]
            if projection_plan is not None and projection_plan["target_family"] != target.id:
                raise RegistryError(
                    f"{class_path}.mapping.source_projection_plan: target family does not match expanded primary"
                )
            primary_target = {
                "id": f"{match_id}.{target.id}",
                "match_id": match_id,
                "class_id": item["id"],
                "signal": item["signal"],
                "role": role,
                "target_kind": "primary",
                "family": target.id,
                "bucket": target.bucket,
                "event_name": target.event_name
                if target.type == "log"
                else target.instrument_name
                if target.type == "metric"
                else target.id,
                "family_schema_version": target.family_schema_version,
                "instrument_name": target.instrument_name,
                "instrument_type": target.instrument_type,
                "instrument_unit": target.metric_unit,
                "field_refs": sorted(use.ref for use in target.resolved_uses),
                "mapping_strategy": item["mapping"]["strategy"],
                "derivation_strategy": item["mapping"]["strategy"] if role == "derive" else None,
                "time_rule": item["time_rule"],
                "outcome_rule": item["outcome_rule"],
                "import_context_id": f"otlp.import.{target.id}" if target.type == "log" and role == "import" else None,
                "source_unit_rule": source_unit_rule,
                "source_projection_plan": projection_plan,
            }
            targets_by_match[match_id] = [primary_target]
            for raw_derived in item["derived_targets"]:
                derived = _inbound_mapping(raw_derived, f"{class_path}.derived_targets")
                family = groups[_string(derived["family"], f"{class_path}.derived_targets.family", pattern=_ID)]
                targets_by_match[match_id].append(
                    {
                        "id": f"{match_id}.{family.id}",
                        "match_id": match_id,
                        "class_id": item["id"],
                        "signal": "metrics",
                        "role": "derive",
                        "target_kind": "derived",
                        "family": family.id,
                        "bucket": family.bucket,
                        "event_name": family.instrument_name,
                        "family_schema_version": family.family_schema_version,
                        "instrument_name": family.instrument_name,
                        "instrument_type": family.instrument_type,
                        "instrument_unit": family.metric_unit,
                        "field_refs": sorted(use.ref for use in family.resolved_uses),
                        "mapping_strategy": item["mapping"]["strategy"],
                        "derivation_strategy": derived["strategy"],
                        "time_rule": item["time_rule"],
                        "outcome_rule": "forbidden",
                        "import_context_id": None,
                        "source_unit_rule": {"kind": "none", "target_unit": "", "accepted": []},
                        "source_projection_plan": None,
                    }
                )
    matches.sort(key=lambda item: item["id"].encode("ascii"))
    if len({item["id"] for item in matches}) != len(matches):
        raise RegistryError(f"{path}.binding_classes: duplicate expanded match ID")
    for left_index, left in enumerate(matches):
        for right in matches[left_index + 1 :]:
            if left["signal"] != right["signal"]:
                continue
            left_sources, right_sources = set(left["sources"]), set(right["sources"])
            if (
                "any_authenticated" not in left_sources
                and "any_authenticated" not in right_sources
                and left_sources.isdisjoint(right_sources)
            ):
                continue
            if not _inbound_disjoint(left, right):
                raise RegistryError(
                    f"{path}.binding_classes: expanded discriminators overlap: {left['id']} and {right['id']}"
                )

    attachments = _inbound_sequence(source["derivation_attachments"], f"{path}.derivation_attachments")
    if attachments != [
        {
            "id": "otlp.genai.duration.span.v1",
            "parent_class": "otlp.genai.span.operation.v1",
            "family": "metric.gen_ai.client.operation.duration",
            "strategy": "elapsed-time-v1",
        }
    ]:
        raise RegistryError(f"{path}.derivation_attachments: contract drift")
    attachment = attachments[0]
    attachment_family = groups[attachment["family"]]
    for match in matches:
        if match["class_id"] != attachment["parent_class"]:
            continue
        targets_by_match[match["id"]].append(
            {
                "id": f"{match['id']}.{attachment_family.id}",
                "match_id": match["id"],
                "class_id": attachment["id"],
                "signal": "metrics",
                "role": "derive",
                "target_kind": "derived",
                "family": attachment_family.id,
                "bucket": attachment_family.bucket,
                "event_name": attachment_family.instrument_name,
                "family_schema_version": attachment_family.family_schema_version,
                "instrument_name": attachment_family.instrument_name,
                "instrument_type": attachment_family.instrument_type,
                "instrument_unit": attachment_family.metric_unit,
                "field_refs": sorted(use.ref for use in attachment_family.resolved_uses),
                "mapping_strategy": match["mapping"]["strategy"],
                "derivation_strategy": attachment["strategy"],
                "time_rule": "span-elapsed-v1",
                "outcome_rule": "forbidden",
                "import_context_id": None,
                "source_unit_rule": {"kind": "none", "target_unit": "", "accepted": []},
                "source_projection_plan": None,
            }
        )
    target_descriptors: list[dict[str, Any]] = []
    for match in matches:
        match_targets = sorted(targets_by_match[match["id"]], key=lambda item: item["id"].encode("ascii"))
        target_ids = [item["id"] for item in match_targets]
        if len(target_ids) != len(set(target_ids)):
            raise RegistryError(f"{path}: duplicate one-target descriptor for {match['id']}")
        match["target_ids"] = target_ids
        target_descriptors.extend(match_targets)
    target_descriptors.sort(key=lambda item: item["id"].encode("ascii"))
    if len({item["id"] for item in target_descriptors}) != len(target_descriptors):
        raise RegistryError(f"{path}: duplicate target descriptor ID")

    native_markers_by_identity: dict[tuple[str, str, str], dict[str, Any]] = {}
    for match in matches:
        if match["shape"] != "native_exact":
            continue
        for predicate in match["discriminator"]["predicates"]:
            location = predicate["location"]
            key = predicate["key"]
            if key.startswith("defenseclaw."):
                marker_kind = "reserved_key_presence"
                marker_values: list[Any] = []
            elif location in {"scope_name", "scope_schema_url"}:
                marker_kind = "exact_structural_value"
                marker_values = list(predicate["values"])
            elif location == "log_body" and predicate["operator"] == "projected_record_json":
                marker_kind = "projected_record_structure"
                marker_values = []
            else:
                continue
            identity = (match["signal"], location, key)
            descriptor = {
                "id": f"otlp.native.marker.{match['signal']}.{location}.{key}",
                "signal": match["signal"],
                "location": location,
                "key": key,
                "marker_kind": marker_kind,
                "values": marker_values,
                "value_type": predicate["value_type"],
            }
            prior = native_markers_by_identity.setdefault(identity, descriptor)
            if prior != descriptor:
                raise RegistryError(f"{path}: inconsistent native marker descriptor {identity}")
    native_markers = sorted(native_markers_by_identity.values(), key=lambda item: item["id"].encode("ascii"))
    if {item["signal"] for item in native_markers} != {"logs", "traces", "metrics"}:
        raise RegistryError(f"{path}: native marker signal coverage is incomplete")

    echo_recognizers: list[dict[str, Any]] = []
    for group in sorted(groups.values(), key=lambda item: item.id.encode("ascii")):
        signal = {"log": "logs", "span": "traces", "metric": "metrics"}.get(group.type)
        if signal is None:
            continue
        echo_recognizers.append(
            {
                "id": f"otlp.echo.{group.id}",
                "signal": signal,
                "family": group.id,
                "bucket": group.bucket,
                "event_name": group.event_name if group.type == "log" else group.id,
                "instrument_name": group.instrument_name,
                "semantic_instance_key": expected_constants["semantic_resource_instance_key"],
                "forward_instance_key": expected_constants["forward_instance_key"],
                "forward_destination_key": expected_constants["forward_destination_key"],
                "forward_hop_count_key": expected_constants["forward_hop_count_key"],
                "forward_placement": "resource" if signal == "metrics" else "leaf",
                "compare_self_with": expected_constants["forward_instance_key"],
                "semantic_instance_is_transport_authority": False,
                "constructs_record": False,
                "mandatory": False,
                "floor": False,
            }
        )
    expected_echo_families = {group.id for group in groups.values() if group.type in {"log", "span", "metric"}}
    if {item["family"] for item in echo_recognizers} != expected_echo_families:
        raise RegistryError(f"{path}: native self-echo recognizer coverage mismatch")

    import_contexts = [
        {
            "id": f"otlp.import.{group.id}",
            "signal": "logs",
            "family_descriptor_id": group.id,
            "bucket": group.bucket,
            "event_name": group.event_name,
            "construction_mode": "ordinary_import_only",
            "capabilities": ["validate", "construct_ordinary"],
        }
        for group in sorted(groups.values(), key=lambda item: item.id.encode("ascii"))
        if group.type == "log"
    ]
    expected_log_families = {group.id for group in groups.values() if group.type == "log"}
    if {item["family_descriptor_id"] for item in import_contexts} != expected_log_families:
        raise RegistryError(f"{path}: import-only log context coverage mismatch")
    fixture_policy = _inbound_mapping(source["fixture_policy"], f"{path}.fixture_policy")
    _exact_keys(
        fixture_policy,
        {"encodings", "classes", "protobuf_representation"},
        set(),
        f"{path}.fixture_policy",
    )
    if (
        _string_list(fixture_policy["encodings"], f"{path}.fixture_policy.encodings", allow_empty=False)
        != ("json", "protobuf")
        or _string_list(fixture_policy["classes"], f"{path}.fixture_policy.classes", allow_empty=False)
        != ("positive", "negative", "single_fault")
        or fixture_policy["protobuf_representation"] != "canonical_protojson"
    ):
        raise RegistryError(f"{path}.fixture_policy: contract drift")
    return InboundOTLPIR(
        version=1,
        max_forward_hops=4,
        unknown_fields="drop_and_count",
        semantic_resource_instance_key=expected_constants["semantic_resource_instance_key"],
        forward_instance_key=expected_constants["forward_instance_key"],
        forward_destination_key=expected_constants["forward_destination_key"],
        forward_hop_count_key=expected_constants["forward_hop_count_key"],
        record_id_key=expected_constants["record_id_key"],
        scope_name=expected_constants["scope_name"],
        scope_schema_url=expected_constants["scope_schema_url"],
        resource_schema_url=expected_constants["resource_schema_url"],
        shape_policy=_freeze_mapping(
            {
                "classes": ["native_exact", "native_malformed", "external"],
                "native_marker_rule": "any_declared_native_marker_selects_native_candidate",
                "structural_marker_rule": "exact_declared_structure_only",
                "native_malformed_disposition": "invalid_record",
                "native_malformed_external_fallback": "forbidden",
            }
        ),
        alias_sets=tuple(_freeze_mapping(item) for item in alias_sets),
        source_normalizers=tuple(_freeze_mapping(item) for item in source_normalizers),
        source_projection_plans=tuple(_freeze_mapping(item) for item in source_projection_plans),
        binding_classes=tuple(_freeze_mapping(item) for item in classes),
        match_descriptors=tuple(_freeze_mapping(item) for item in matches),
        target_descriptors=tuple(_freeze_mapping(item) for item in target_descriptors),
        native_markers=tuple(_freeze_mapping(item) for item in native_markers),
        echo_recognizers=tuple(_freeze_mapping(item) for item in echo_recognizers),
        import_contexts=tuple(_freeze_mapping(item) for item in import_contexts),
        derivation_attachments=tuple(_freeze_mapping(item) for item in attachments),
        fixture_policy=_freeze_mapping(fixture_policy),
    )


def _validate_entity_lifecycle(
    *,
    entity: str,
    introduced_in: str | None,
    deprecated_in: str | None,
    removed_in: str | None,
    stability: str,
    registry_version: int,
) -> bool:
    if introduced_in is None:
        raise RegistryError(f"{entity}.introduced_in: required")
    introduced = _lifecycle_registry_version(introduced_in, f"{entity}.introduced_in")
    deprecated = (
        _lifecycle_registry_version(deprecated_in, f"{entity}.deprecated_in") if deprecated_in is not None else None
    )
    removed = _lifecycle_registry_version(removed_in, f"{entity}.removed_in") if removed_in is not None else None
    if introduced > registry_version:
        raise RegistryError(f"{entity}.introduced_in: exceeds current registry version")
    if deprecated is not None and deprecated < introduced:
        raise RegistryError(f"{entity}.deprecated_in: precedes introduced_in")
    if deprecated is not None and deprecated > registry_version:
        raise RegistryError(f"{entity}.deprecated_in: exceeds current registry version")
    if (stability == "deprecated") != (deprecated is not None):
        raise RegistryError(f"{entity}: deprecated stability and deprecated_in must agree")
    if removed is not None:
        if deprecated is None:
            raise RegistryError(f"{entity}.deprecated_in: required before removal")
        if removed <= deprecated:
            raise RegistryError(f"{entity}.removed_in: must follow deprecated_in")
    return removed is None or registry_version < removed


def compile_registry(root: Path) -> RegistryIR:
    root = root.resolve()
    registry_path = root / "schemas/telemetry/v8/registry.yaml"
    registry_raw, registry = _load_yaml_strict_with_bytes(registry_path)
    _exact_keys(
        registry,
        {
            "schema_version",
            "registry_version",
            "bucket_catalog_version",
            "imports",
            "dependency_lock",
            "examples",
            "inbound_bindings",
            "semantic_profiles",
            "normalizers",
            "conditions",
            "mandatory_rule_catalog",
            "structured_types",
            "structured_bindings",
            "go_symbol_policy",
            "value_catalogs",
            "structural_contract",
            "metric_defaults",
            "metric_compatibility_profiles",
        },
        {"go_symbol_overrides"},
        "schemas/telemetry/v8/registry.yaml",
    )
    schema_version = _integer(registry["schema_version"], "registry.schema_version")
    if schema_version != 1:
        raise RegistryError("registry.schema_version: unsupported version")
    registry_version = _integer(registry["registry_version"], "registry.registry_version")
    bucket_catalog_version = _integer(registry["bucket_catalog_version"], "registry.bucket_catalog_version")
    imports = _string_list(registry["imports"], "registry.imports", allow_empty=False)
    if imports != EXPECTED_IMPORTS:
        raise RegistryError(f"registry.imports: expected canonical order {EXPECTED_IMPORTS}")
    lock_relative = _string(registry["dependency_lock"], "registry.dependency_lock")
    if lock_relative != "schemas/telemetry/v8/semconv.lock.yaml":
        raise RegistryError("registry.dependency_lock: unexpected path")
    dependencies, lock_digest, structural_documents, structural_input_digests = _parse_lock(root, lock_relative)
    producer_inventory, metric_inventory, v7_exporter_selection, inventory_digest = _parse_producer_inventory(root)
    v7_exporter_selection_schema, v7_exporter_selection_schema_digest = _read_v7_exporter_selection_schema(root)
    normalizers = _parse_normalizer_catalog(registry["normalizers"], "registry.normalizers")
    normalizers_by_id = {item.id: item for item in normalizers}
    structured_types = _parse_structured_types(
        registry["structured_types"],
        "registry.structured_types",
        normalizers_by_id,
    )
    structured_types, structured_property_dispositions = _validate_structural_inputs(
        structural_documents,
        structured_types,
    )
    structured_bindings = _parse_structured_bindings(
        registry["structured_bindings"],
        "registry.structured_bindings",
        structured_types,
    )
    go_symbol_policy, go_symbol_overrides = _parse_go_symbol_contract(
        registry["go_symbol_policy"],
        registry.get("go_symbol_overrides"),
    )
    conditions = _parse_conditions(registry["conditions"], "registry.conditions")
    mandatory_rule_catalog = _parse_mandatory_rule_catalog(
        registry["mandatory_rule_catalog"],
        "registry.mandatory_rule_catalog",
    )
    mandatory_rule_ids = frozenset(rule.id for rule in mandatory_rule_catalog.rules)
    value_catalogs = _parse_value_catalogs(registry["value_catalogs"], "registry.value_catalogs")
    structural_contract = _parse_structural_contract(
        registry["structural_contract"],
        "registry.structural_contract",
        normalizers_by_id,
    )
    metric_cardinality_limit, metric_compatibility_profile = _parse_metric_settings(
        registry["metric_defaults"],
        registry["metric_compatibility_profiles"],
    )
    profiles = registry["semantic_profiles"]
    if not isinstance(profiles, list) or len(profiles) != 1 or not isinstance(profiles[0], dict):
        raise RegistryError("registry.semantic_profiles: expected one profile")
    profile = profiles[0]
    _exact_keys(
        profile,
        {
            "id",
            "trace_schema_version",
            "gen_ai_semconv_profile",
            "openinference_profile",
            "galileo_compatibility_profile",
        },
        set(),
        "registry.semantic_profiles[0]",
    )
    for key, value in profile.items():
        _string(value, f"registry.semantic_profiles[0].{key}", pattern=_ID)
    if profile != EXPECTED_SEMANTIC_PROFILE:
        raise RegistryError("registry.semantic_profiles[0]: profile tuple does not match defenseclaw-genai-rich-v1")
    dependency_by_id = {item.id: item for item in dependencies}
    if profile["gen_ai_semconv_profile"] != dependency_by_id["otel_genai"].profile_id:
        raise RegistryError("registry.semantic_profiles[0].gen_ai_semconv_profile: lock mismatch")
    if profile["openinference_profile"] != dependency_by_id["openinference"].profile_id:
        raise RegistryError("registry.semantic_profiles[0].openinference_profile: lock mismatch")
    semantic_profiles = (
        SemanticProfileIR(
            profile["id"],
            profile["trace_schema_version"],
            profile["gen_ai_semconv_profile"],
            profile["openinference_profile"],
            profile["galileo_compatibility_profile"],
        ),
    )
    domains: list[DomainIR] = []
    domain_digests: list[InputDigest] = []
    for relative, expected_domain in zip(imports, EXPECTED_DOMAINS, strict=True):
        domain, digest = _parse_domain(
            root,
            relative,
            expected_domain,
            normalizers_by_id,
            mandatory_rule_ids,
        )
        domains.append(domain)
        domain_digests.append(digest)
    active_domains: list[DomainIR] = []
    for domain in domains:
        active_attributes = tuple(
            attribute
            for attribute in domain.attributes
            if _validate_entity_lifecycle(
                entity=f"attribute {attribute.id}",
                introduced_in=attribute.introduced_in,
                deprecated_in=attribute.deprecated_in,
                removed_in=attribute.removed_in,
                stability=attribute.stability,
                registry_version=registry_version,
            )
        )
        active_groups: list[GroupIR] = []
        for group in domain.groups:
            active = _validate_entity_lifecycle(
                entity=f"group {group.id}",
                introduced_in=group.introduced_in,
                deprecated_in=group.deprecated_in,
                removed_in=group.removed_in,
                stability=group.stability,
                registry_version=registry_version,
            )
            if not active and group.route_selector is True:
                raise RegistryError(f"group {group.id}: removed group cannot remain route-selectable")
            if active:
                active_groups.append(group)
        active_domains.append(
            replace(
                domain,
                attributes=active_attributes,
                groups=tuple(active_groups),
            )
        )
    domains = active_domains
    attribute_owners: dict[str, str] = {}
    upstream_attributes: dict[str, tuple[str, SnapshotAttribute]] = {}
    for dependency in dependencies:
        for attribute in dependency.snapshot.attributes:
            if attribute.id in upstream_attributes:
                raise RegistryError(f"upstream attribute {attribute.id}: duplicate selected ownership")
            upstream_attributes[attribute.id] = (dependency.id, attribute)
            attribute_owners[attribute.id] = _public_upstream_owner(dependency.id)
    extension_refs = {extension.ref for domain in domains for extension in domain.attribute_extensions}
    selected_by_dependency = {
        dependency.id: {attribute.id for attribute in dependency.snapshot.attributes}
        for dependency in dependencies
    }
    if selected_by_dependency["otel_core"] & selected_by_dependency["otel_genai"]:
        raise RegistryError("selected OTel semantic-convention ownership overlaps")
    selected_otel_attributes = selected_by_dependency["otel_core"] | selected_by_dependency["otel_genai"]
    if selected_otel_attributes != extension_refs:
        missing = sorted(selected_otel_attributes - extension_refs)
        extra = sorted(extension_refs - selected_otel_attributes)
        raise RegistryError(
            "selected OTel semantic-convention attributes differ from authored extension closure "
            f"missing={missing} extra={extra}"
        )
    if selected_by_dependency["openinference"] != REQUIRED_OPENINFERENCE_ATTRIBUTES:
        raise RegistryError("selected OpenInference attributes differ from runtime profile vocabulary")
    upstream_attribute_ownership = tuple(
        UpstreamAttributeOwnershipIR(reference, attribute_owners[reference])
        for reference in sorted(upstream_attributes)
    )
    local_attributes: dict[str, AttributeIR] = {}
    for domain in domains:
        for attribute in domain.attributes:
            if attribute.id in attribute_owners:
                raise RegistryError(f"attribute {attribute.id}: duplicate ownership")
            attribute_owners[attribute.id] = domain.domain
            local_attributes[attribute.id] = attribute
    _validate_value_catalog_attributes(value_catalogs, local_attributes)
    group_owners: dict[str, GroupIR] = {}
    for domain in domains:
        for group in domain.groups:
            if group.id in group_owners:
                raise RegistryError(f"group {group.id}: duplicate ownership")
            group_owners[group.id] = group
    _validate_condition_references(group_owners, conditions, local_attributes, upstream_attributes)
    _validate_structural_contract_bindings(
        structural_contract,
        schema_version,
        bucket_catalog_version,
        semantic_profiles,
        group_owners,
        local_attributes,
        upstream_attributes,
    )
    _validate_outcome_contracts(group_owners, local_attributes)
    log_event_names = [
        group.event_name for group in group_owners.values() if group.type == "log" and group.event_name is not None
    ]
    if len(log_event_names) != len(set(log_event_names)):
        raise RegistryError("log families: duplicate event_name")
    compatibility_names = set(log_event_names) & EXPECTED_COMPATIBILITY_LOG_IDENTITIES
    if compatibility_names != EXPECTED_COMPATIBILITY_LOG_IDENTITIES:
        raise RegistryError("log families: compatibility identity inventory mismatch")
    dotted_names = set(log_event_names) - compatibility_names
    if not dotted_names or any("." not in name for name in dotted_names):
        raise RegistryError("log families: canonical non-compatibility identities must be dotted")
    producer_keys: dict[str, set[str]] = {producer: set() for producer in EXPECTED_PRODUCER_KINDS}
    for domain in domains:
        for mapping in domain.producer_mappings:
            if mapping.key in producer_keys[mapping.producer]:
                raise RegistryError(f"producer mapping: duplicate {mapping.producer}/{mapping.key}")
            producer_keys[mapping.producer].add(mapping.key)
    for producer, expected in producer_inventory.items():
        if producer_keys[producer] != expected:
            missing = sorted(expected - producer_keys[producer])
            extra = sorted(producer_keys[producer] - expected)
            raise RegistryError(f"producer mappings {producer}: inventory mismatch missing={missing} extra={extra}")
    for domain in domains:
        for attribute in domain.attributes:
            if attribute.alias_of is not None and attribute.alias_of not in attribute_owners:
                raise RegistryError(f"attribute {attribute.id}: unknown alias_of reference")
            if attribute.projection_only:
                target = local_attributes.get(attribute.alias_of or "")
                if (
                    attribute.alias_of is None
                    or target is None
                    or target.projection_only
                    or attribute.stability != "deprecated"
                    or attribute.deprecated_in is None
                    or attribute.removed_in is None
                    or attribute.owner != "defenseclaw"
                ):
                    raise RegistryError(f"attribute {attribute.id}: invalid projection-only alias lifecycle")
            elif attribute.alias_of is not None:
                raise RegistryError(f"attribute {attribute.id}: aliases must be projection-only")
            if attribute.id.startswith("gen_ai."):
                if (
                    not attribute.projection_only
                    or attribute.alias_of is None
                    or not attribute.alias_of.startswith("defenseclaw.")
                ):
                    raise RegistryError(
                        f"attribute {attribute.id}: non-upstream gen_ai.* must be a projection-only alias"
                    )
        for group in domain.groups:
            for parent in group.extends:
                if parent not in group_owners:
                    raise RegistryError(f"group {group.id}: unknown extends reference")
            for reference in group.attribute_refs:
                if reference not in attribute_owners:
                    raise RegistryError(f"group {group.id}: unknown attribute reference")
                local_attribute = local_attributes.get(reference)
                if local_attribute is not None and local_attribute.projection_only:
                    raise RegistryError(f"group {group.id}: projection-only alias cannot be a canonical field")
            for event in group.event_refs or ():
                if event.startswith("event."):
                    raise RegistryError(f"group {group.id}: events must use public names without event. prefix")
                target = group_owners.get(f"event.{event}")
                if target is None or target.type != "span_event":
                    raise RegistryError(f"group {group.id}: unknown span-event reference")
        for mapping in domain.producer_mappings:
            identities = (
                () if mapping.default_identity is None else (mapping.default_identity,)
            ) + mapping.allowed_context_identities
            for identity in identities:
                if identity.compatibility_only:
                    continue
                target = group_owners.get(identity.family or "")
                if target is None or target.type != "log":
                    raise RegistryError(f"producer mapping: unknown log family {identity.family}")
                if target.event_name != identity.event_name:
                    raise RegistryError(f"producer mapping {identity.event_name}: family event_name mismatch")
                if target.bucket != identity.bucket:
                    raise RegistryError(f"producer mapping {identity.event_name}: family bucket mismatch")
    upstream_extensions: dict[str, AttributeExtensionIR] = {}
    for domain in domains:
        for extension in domain.attribute_extensions:
            if extension.ref in upstream_extensions:
                raise RegistryError(f"attribute extension {extension.ref}: duplicate extension")
            if extension.ref not in upstream_attributes:
                raise RegistryError(f"attribute extension {extension.ref}: expected canonical upstream attribute")
            upstream = upstream_attributes[extension.ref][1]
            _validate_normalization_compatibility(
                extension.normalization,
                upstream.allowed_types,
                upstream.shape,
                f"attribute extension {extension.ref}.normalization",
            )
            upstream_extensions[extension.ref] = extension
    referenced_upstream = {
        reference
        for group in group_owners.values()
        for reference in group.attribute_refs
        if reference in upstream_attributes
    }
    if set(upstream_extensions) != referenced_upstream:
        missing = sorted(referenced_upstream - set(upstream_extensions))
        unreferenced = sorted(set(upstream_extensions) - referenced_upstream)
        raise RegistryError(f"attribute extensions: coverage mismatch missing={missing} unreferenced={unreferenced}")
    for binding in structured_bindings:
        upstream = upstream_attributes.get(binding.attribute)
        extension = upstream_extensions.get(binding.attribute)
        if (
            upstream is None
            or upstream[0] != "otel_genai"
            or upstream[1].shape != "any_value"
            or extension is None
            or extension.field_class != "content"
            or extension.sensitivity != "sensitive"
        ):
            raise RegistryError(f"structured binding {binding.attribute}: incompatible upstream attribute/privacy")
    _validate_attribute_use_constraints(
        group_owners,
        local_attributes,
        upstream_extensions,
        upstream_attributes,
    )
    _validate_alias_cycles(domains)
    resolved_domains, group_resolution_order, resolved_group_uses = _resolve_group_uses(tuple(domains))
    domains = list(resolved_domains)
    group_owners = {group.id: group for domain in domains for group in domain.groups}
    inbound_bindings = _parse_inbound_otlp(registry["inbound_bindings"], groups=group_owners)
    v7_exporter_selection = _materialize_v7_exporter_selection(
        v7_exporter_selection,
        domains,
        producer_inventory,
        metric_inventory,
    )
    _validate_v7_exporter_selection(
        v7_exporter_selection,
        v7_exporter_selection_schema,
        schema_version=schema_version,
        registry_version=registry_version,
        groups=group_owners,
        domains=domains,
        producer_inventory=producer_inventory,
    )
    _validate_trace_derivation_coverage(structural_contract, group_owners)
    _validate_metric_attribute_safety(
        group_owners,
        local_attributes,
        upstream_extensions,
        upstream_attributes,
        metric_compatibility_profile,
        metric_inventory,
    )
    _validate_span_name_patterns(
        group_owners,
        local_attributes,
        upstream_extensions,
        upstream_attributes,
    )
    go_symbol_table = _build_go_symbol_table(
        go_symbol_policy,
        go_symbol_overrides,
        domains=tuple(domains),
        upstream_extensions=upstream_extensions,
        conditions=conditions,
        value_catalogs=value_catalogs,
        semantic_profiles=semantic_profiles,
        structured_types=structured_types,
    )
    group_signals = {
        group.id: _SIGNAL_BY_GROUP_TYPE[group.type]
        for group in group_owners.values()
        if group.type in _SIGNAL_BY_GROUP_TYPE
    }
    examples_relative = _string(registry["examples"], "registry.examples")
    if examples_relative != "examples.yaml":
        raise RegistryError("registry.examples: expected examples.yaml")
    examples, examples_digest = _parse_examples(
        root,
        examples_relative,
        group_signals,
        group_owners,
        local_attributes,
        upstream_extensions,
        upstream_attributes,
        structural_contract,
        conditions,
        mandatory_rule_catalog,
        value_catalogs,
        semantic_profiles,
    )
    registry_digest = InputDigest("schemas/telemetry/v8/registry.yaml", _sha256(registry_raw))
    input_digests = (
        registry_digest,
        v7_exporter_selection_schema_digest,
        *domain_digests,
        lock_digest,
        *structural_input_digests,
        inventory_digest,
        examples_digest,
    )
    registry_values: dict[str, Any] = {
        "registry_path": "schemas/telemetry/v8/registry.yaml",
        "schema_version": schema_version,
        "registry_version": registry_version,
        "bucket_catalog_version": bucket_catalog_version,
        "imports": imports,
        "dependency_lock_path": lock_relative,
        "examples_path": examples_relative,
        "v7_exporter_selection_schema_path": V7_EXPORTER_SELECTION_SCHEMA.as_posix(),
        "input_digests": tuple(input_digests),
        "dependencies": dependencies,
        "semantic_profiles": semantic_profiles,
        "go_symbol_policy": go_symbol_policy,
        "go_symbol_overrides": go_symbol_overrides,
        "go_symbol_table": go_symbol_table,
        "normalizers": normalizers,
        "conditions": conditions,
        "mandatory_rule_catalog": mandatory_rule_catalog,
        "structured_types": structured_types,
        "structured_bindings": structured_bindings,
        "structured_property_dispositions": structured_property_dispositions,
        "value_catalogs": value_catalogs,
        "structural_contract": structural_contract,
        "metric_cardinality_limit": metric_cardinality_limit,
        "metric_compatibility_profile": metric_compatibility_profile,
        "v7_exporter_selection": v7_exporter_selection,
        "v7_exporter_selection_schema": v7_exporter_selection_schema,
        "inbound_bindings": inbound_bindings,
        "domains": tuple(domains),
        "group_resolution_order": group_resolution_order,
        "resolved_group_uses": resolved_group_uses,
        "examples": examples,
        "upstream_attribute_ownership": upstream_attribute_ownership,
        "legacy_only_upstream_attributes": (),
    }
    materialized_view = _build_materialized_registry_view(registry_values)
    return RegistryIR(
        **registry_values,
        materialized_view=materialized_view,
    )


_REQUIREMENT_RANK: Final = {
    "optional": 1,
    "recommended": 2,
    "conditional": 3,
    "required": 4,
}


def _intersect_use_constraints(
    group_id: str,
    reference: str,
    origins: tuple[AttributeUseOriginIR, ...],
) -> Mapping[str, FrozenJSON]:
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

    def enum_marker(value: FrozenJSON) -> tuple[type[Any], FrozenJSON]:
        return type(value), value

    for origin in origins:
        for key, value in origin.constraints.items():
            if key == "enum":
                incoming = tuple(value) if isinstance(value, tuple) else ()
                if "enum" not in result:
                    result["enum"] = incoming
                else:
                    allowed = {enum_marker(item) for item in incoming}
                    result["enum"] = tuple(item for item in result["enum"] if enum_marker(item) in allowed)
                if not result["enum"]:
                    raise RegistryError(f"group {group_id}: empty enum intersection for {reference}")
            elif key == "pattern":
                if "pattern" in result and result["pattern"] != value:
                    raise RegistryError(f"group {group_id}: nonrepresentable pattern intersection for {reference}")
                result["pattern"] = value
            elif key in minimum_keys:
                result[key] = value if key not in result else max(result[key], value)
            elif key in maximum_keys:
                result[key] = value if key not in result else min(result[key], value)
            else:
                raise RegistryError(f"group {group_id}: unsupported merged constraint {key} for {reference}")
    for minimum, maximum in (("min", "max"), ("min_items", "max_items")):
        if minimum in result and maximum in result and result[minimum] > result[maximum]:
            raise RegistryError(f"group {group_id}: inconsistent {minimum}/{maximum} intersection for {reference}")
    if (
        "max_item_utf8_bytes" in result
        and "max_utf8_bytes" in result
        and result["max_item_utf8_bytes"] > result["max_utf8_bytes"]
    ):
        raise RegistryError(f"group {group_id}: incompatible UTF-8 bounds for {reference}")
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
            raise RegistryError(f"group {group_id}: empty constrained enum intersection for {reference}")
        result["enum"] = enum_values
    return _freeze_mapping(result)


def _resolve_group_uses(
    domains: tuple[DomainIR, ...],
) -> tuple[
    tuple[DomainIR, ...],
    tuple[str, ...],
    Mapping[str, tuple[ResolvedAttributeUseIR, ...]],
]:
    groups = {group.id: group for domain in domains for group in domain.groups}
    state: dict[str, int] = {}
    resolved: dict[str, tuple[ResolvedAttributeUseIR, ...]] = {}
    order: list[str] = []

    def visit(group_id: str) -> tuple[ResolvedAttributeUseIR, ...]:
        current_state = state.get(group_id, 0)
        if current_state == 1:
            raise RegistryError(f"group {group_id}: inheritance cycle")
        if current_state == 2:
            return resolved[group_id]
        group = groups.get(group_id)
        if group is None:
            raise RegistryError(f"group {group_id}: unknown inheritance target")
        state[group_id] = 1
        if group.type == "attribute_group":
            allowed_parent_types = {"attribute_group"}
            resolved_role = "attributes"
        elif group.type == "body_group":
            allowed_parent_types = {"attribute_group", "body_group"}
            resolved_role = "body_fields"
        elif group.type == "log":
            if len(group.extends) != 1:
                raise RegistryError(f"group {group.id}: log must extend exactly one body_group")
            allowed_parent_types = {"body_group"}
            resolved_role = "body_fields"
        else:
            allowed_parent_types = {"attribute_group"}
            resolved_role = "attributes"

        contributions: dict[str, list[AttributeUseOriginIR]] = {}
        reference_order: list[str] = []

        def contribute(reference: str, origins: tuple[AttributeUseOriginIR, ...]) -> None:
            if reference not in contributions:
                contributions[reference] = []
                reference_order.append(reference)
            for origin in origins:
                if origin not in contributions[reference]:
                    contributions[reference].append(origin)

        for parent_id in group.extends:
            parent = groups.get(parent_id)
            if parent is None:
                raise RegistryError(f"group {group.id}: unknown extends reference {parent_id}")
            if parent.type not in allowed_parent_types:
                raise RegistryError(f"group {group.id}: incompatible {parent.type} parent {parent_id}")
            for inherited in visit(parent_id):
                if resolved_role == "attributes" and inherited.role != "attributes":
                    raise RegistryError(f"group {group.id}: body role crosses into attribute family via {parent_id}")
                contribute(inherited.ref, inherited.origins)

        for direct in group.attribute_uses:
            if resolved_role == "attributes" and direct.role != "attributes":
                raise RegistryError(f"group {group.id}: body_fields are not allowed for {group.type}")
            origin = AttributeUseOriginIR(
                group.id,
                direct.role,
                direct.requirement_level,
                direct.conditional,
                direct.constraints,
            )
            contribute(direct.ref, (origin,))

        materialized: list[ResolvedAttributeUseIR] = []
        for reference in reference_order:
            origins = tuple(contributions[reference])
            dominant = max(
                origins,
                key=lambda origin: _REQUIREMENT_RANK[origin.requirement_level],
            ).requirement_level
            dominant_origins = tuple(origin for origin in origins if origin.requirement_level == dominant)
            clauses = tuple(dict.fromkeys(origin.conditional for origin in dominant_origins))
            if len(clauses) != 1:
                raise RegistryError(f"group {group.id}: conflicting dominant conditional clauses for {reference}")
            conditional = clauses[0]
            if dominant == "conditional" and conditional is None:
                raise RegistryError(f"group {group.id}: dominant conditional clause is absent for {reference}")
            materialized.append(
                ResolvedAttributeUseIR(
                    reference,
                    resolved_role,
                    dominant,
                    conditional,
                    _intersect_use_constraints(group.id, reference, origins),
                    origins,
                )
            )
        result = tuple(materialized)
        resolved[group_id] = result
        state[group_id] = 2
        order.append(group_id)
        return result

    for domain in domains:
        for group in domain.groups:
            visit(group.id)
    updated_domains = tuple(
        replace(
            domain,
            groups=tuple(replace(group, resolved_uses=resolved[group.id]) for group in domain.groups),
        )
        for domain in domains
    )
    ordered_mapping = MappingProxyType({group_id: resolved[group_id] for group_id in order})
    return updated_domains, tuple(order), ordered_mapping


def _validate_alias_cycles(domains: list[DomainIR]) -> None:
    aliases = {
        attribute.id: attribute.alias_of
        for domain in domains
        for attribute in domain.attributes
        if attribute.alias_of is not None
    }
    for start in sorted(aliases):
        seen: set[str] = set()
        current: str | None = start
        while current in aliases:
            if current in seen:
                raise RegistryError(f"attribute {start}: alias cycle")
            seen.add(current)
            current = aliases[current]


def _validate_outcome_contracts(
    groups: Mapping[str, GroupIR],
    local_attributes: Mapping[str, AttributeIR],
) -> None:
    outcome_attribute = local_attributes.get("defenseclaw.outcome")
    if outcome_attribute is None:
        raise RegistryError("attribute defenseclaw.outcome: canonical outcome enum is missing")
    raw_vocabulary = outcome_attribute.normalization.effective_constraints.get("enum")
    if (
        not isinstance(raw_vocabulary, tuple)
        or not raw_vocabulary
        or not all(isinstance(item, str) for item in raw_vocabulary)
    ):
        raise RegistryError("attribute defenseclaw.outcome: expected ordered string enum")
    vocabulary = tuple(raw_vocabulary)
    positions = {outcome: index for index, outcome in enumerate(vocabulary)}
    if len(positions) != len(vocabulary):
        raise RegistryError("attribute defenseclaw.outcome: duplicate canonical outcome")
    for group in groups.values():
        if group.type in {"log", "span"}:
            if group.outcome_requirement is None or group.allowed_outcomes is None:
                raise RegistryError(f"group {group.id}: logs/spans require outcome_requirement and allowed_outcomes")
            if group.outcome_requirement == "forbidden":
                if group.allowed_outcomes:
                    raise RegistryError(f"group {group.id}: forbidden outcome requires an empty allowed_outcomes")
                continue
            if not group.allowed_outcomes:
                raise RegistryError(f"group {group.id}: required/optional outcome requires nonempty allowed_outcomes")
            unknown = [item for item in group.allowed_outcomes if item not in positions]
            if unknown:
                raise RegistryError(f"group {group.id}: allowed_outcomes contains unknown outcome values {unknown}")
            indexes = tuple(positions[item] for item in group.allowed_outcomes)
            if indexes != tuple(sorted(indexes)):
                raise RegistryError(f"group {group.id}: allowed_outcomes must follow defenseclaw.outcome order")
            if group.allowed_outcomes == vocabulary:
                raise RegistryError(f"group {group.id}: globally broad allowed_outcomes is forbidden")
        elif group.outcome_requirement is not None or group.allowed_outcomes is not None:
            raise RegistryError(f"group {group.id}: outcome contract is allowed only on logs/spans")


def _validate_attribute_use_constraints(
    groups: dict[str, GroupIR],
    local_attributes: dict[str, AttributeIR],
    upstream_extensions: dict[str, AttributeExtensionIR],
    upstream_attributes: dict[str, tuple[str, SnapshotAttribute]],
) -> None:
    numeric_types = {"int64", "uint32", "double", "int64[]", "double[]"}
    array_types = {"string[]", "boolean[]", "int64[]", "double[]", "array"}
    string_types = {"string", "string[]"}
    for group in groups.values():
        for use in group.attribute_uses:
            if not use.constraints:
                continue
            local = local_attributes.get(use.ref)
            extension = upstream_extensions.get(use.ref)
            if local is not None:
                field_types = (local.field_type,)
                shape = "attribute"
                normalization = local.normalization
            elif extension is not None:
                upstream = upstream_attributes[use.ref][1]
                field_types = upstream.allowed_types
                shape = upstream.shape
                normalization = extension.normalization
            else:
                raise RegistryError(f"group {group.id}: constrained attribute {use.ref} has no metadata")
            types = set(field_types)
            structured = shape in {"any_value", "indexed_prefix", "object_prefix"} or bool(types & {"object", "array"})
            constraints = use.constraints
            if "enum" in constraints:
                enum_types = types or {"object"}
                for value in constraints["enum"]:
                    compatible = (
                        (type(value) is str and bool(enum_types & string_types))
                        or (type(value) is bool and bool(enum_types & {"boolean", "boolean[]"}))
                        or (type(value) is int and bool(enum_types & numeric_types))
                        or (type(value) is float and bool(enum_types & {"double", "double[]"}))
                    )
                    if not compatible:
                        raise RegistryError(f"group {group.id}: constraint enum type is incompatible with {use.ref}")
            if "pattern" in constraints and (not types or not types.issubset(string_types)):
                raise RegistryError(f"group {group.id}: pattern constraint is incompatible with {use.ref}")
            if ({"min", "max"} & constraints.keys()) and (not types or not types.issubset(numeric_types)):
                raise RegistryError(f"group {group.id}: numeric constraint is incompatible with {use.ref}")
            if types & {"int64", "uint32", "int64[]"} and any(
                key in constraints and type(constraints[key]) is not int for key in ("min", "max")
            ):
                raise RegistryError(f"group {group.id}: integer use constraints must be exact integers for {use.ref}")
            if ({"min_items", "max_items"} & constraints.keys()) and not (bool(types & array_types) or structured):
                raise RegistryError(f"group {group.id}: item constraint is incompatible with {use.ref}")
            if constraints.get("min_items", 0) > 1 and (shape == "any_value" or "canonical_json" in types):
                raise RegistryError(f"group {group.id}: min_items greater than one is unsupported for {use.ref}")
            if ({"max_utf8_bytes"} & constraints.keys()) and not (
                bool(types & (string_types | {"bytes"})) or structured
            ):
                raise RegistryError(f"group {group.id}: byte constraint is incompatible with {use.ref}")
            if ({"max_item_utf8_bytes"} & constraints.keys()) and not ("string[]" in types or structured):
                raise RegistryError(f"group {group.id}: per-item byte constraint is incompatible with {use.ref}")
            if ({"max_depth", "max_properties"} & constraints.keys()) and not structured:
                raise RegistryError(f"group {group.id}: structured constraint is incompatible with {use.ref}")
            effective = normalization.effective_constraints
            if "pattern" in constraints and "pattern" in effective and constraints["pattern"] != effective["pattern"]:
                raise RegistryError(f"group {group.id}: nonrepresentable pattern intersection for {use.ref}")
            for maximum in (
                "max",
                "max_items",
                "max_utf8_bytes",
                "max_item_utf8_bytes",
                "max_depth",
                "max_properties",
            ):
                if maximum in constraints and maximum in effective and constraints[maximum] > effective[maximum]:
                    raise RegistryError(f"group {group.id}: {maximum} weakens normalization for {use.ref}")
            for minimum in ("min", "min_items"):
                if minimum in constraints and minimum in effective and constraints[minimum] < effective[minimum]:
                    raise RegistryError(f"group {group.id}: {minimum} weakens normalization for {use.ref}")
            if (
                "enum" in constraints
                and "enum" in effective
                and not set(constraints["enum"]).issubset(effective["enum"])
            ):
                raise RegistryError(f"group {group.id}: enum constraint weakens normalization for {use.ref}")


def _validate_metric_attribute_safety(
    groups: dict[str, GroupIR],
    local_attributes: dict[str, AttributeIR],
    upstream_extensions: dict[str, AttributeExtensionIR],
    upstream_attributes: dict[str, tuple[str, SnapshotAttribute]],
    compatibility_profile: MetricCompatibilityProfileIR,
    metric_inventory: dict[str, MetricInventoryIR],
) -> None:
    metric_groups = [group for group in groups.values() if group.type == "metric"]
    instruments = [group.instrument_name for group in metric_groups]
    if None in instruments or len(instruments) != len(set(instruments)):
        raise RegistryError("metric families: instrument names must be present and unique")
    if not set(metric_inventory).issubset(instruments):
        raise RegistryError("metric families: legacy inventory contains an unknown instrument")
    profile_exceptions: dict[str, frozenset[str]] = {}
    prohibited_classes = {"content", "credential", "path", "evidence", "reason", "error"}
    for group in metric_groups:
        assert group.instrument_name is not None
        if group.id != f"metric.{group.instrument_name}":
            raise RegistryError(f"metric {group.id}: family ID must be metric.<instrument_name>")
        labels = frozenset(use.ref for use in group.resolved_uses)
        if bool(labels) == bool(group.empty_labels_reason):
            requirement = "forbidden" if labels else "required"
            raise RegistryError(f"metric {group.id}: empty_labels_reason is {requirement} for this label set")
        projections_by_profile = {item.profile: item for item in group.metric_projections}
        projection = projections_by_profile.get(compatibility_profile.id)
        projected = set(labels)
        if projection is not None:
            mappings = dict(projection.mappings)
            unknown = mappings.keys() - labels
            if unknown:
                raise RegistryError(f"metric {group.id}: projection references unknown labels {sorted(unknown)}")
            projected = {mappings.get(reference, reference) for reference in labels}
            if len(projected) != len(labels):
                raise RegistryError(f"metric {group.id}: projected label collision")
        inventory = metric_inventory.get(group.instrument_name)
        if inventory is not None:
            if group.instrument_type != inventory.instrument_type:
                raise RegistryError(
                    f"metric {group.id}: instrument_type {group.instrument_type!r} differs from "
                    f"legacy inventory {inventory.instrument_type!r}"
                )
            if group.metric_unit != inventory.unit:
                raise RegistryError(
                    f"metric {group.id}: unit {group.metric_unit!r} differs from legacy inventory {inventory.unit!r}"
                )
            if projected != inventory.labels:
                raise RegistryError(
                    f"metric {group.id}: local-observability label mismatch "
                    f"missing={sorted(inventory.labels - projected)} extra={sorted(projected - inventory.labels)}"
                )
            if group.empty_labels_reason != inventory.empty_labels_reason:
                raise RegistryError(f"metric {group.id}: empty-label reason differs from legacy inventory")
        high_labels: set[str] = set()
        for reference in labels:
            local = local_attributes.get(reference)
            extension = upstream_extensions.get(reference)
            if local is not None:
                field_class = local.field_class
                cardinality = local.cardinality
                normalization = local.normalization
                field_types = (local.field_type,)
                if not reference.startswith("defenseclaw."):
                    raise RegistryError(f"metric {group.id}: local canonical label {reference} must use defenseclaw.*")
            elif extension is not None:
                field_class = extension.field_class
                cardinality = extension.cardinality
                normalization = extension.normalization
                field_types = upstream_attributes[reference][1].allowed_types
            else:
                raise RegistryError(f"metric {group.id}: attribute {reference} has no privacy metadata")
            if field_class in prohibited_classes:
                raise RegistryError(
                    f"metric {group.id}: unsafe label attribute {reference} "
                    f"class={field_class} cardinality={cardinality}"
                )
            if cardinality == "high":
                high_labels.add(reference)
            if set(field_types) & {"string", "string[]"}:
                if normalization.id not in {"enum-v1", "bounded-v1", "identifier-v1"}:
                    raise RegistryError(
                        f"metric {group.id}: string label {reference} uses unbounded normalizer {normalization.id}"
                    )
                if "max_utf8_bytes" not in normalization.effective_constraints:
                    raise RegistryError(f"metric {group.id}: string label {reference} lacks max_utf8_bytes")
        if high_labels:
            profile_exceptions[group.instrument_name] = labels
    configured_exceptions = {
        family: frozenset(labels) for family, labels in compatibility_profile.high_cardinality_families.items()
    }
    if profile_exceptions != configured_exceptions:
        missing = sorted(profile_exceptions.keys() - configured_exceptions.keys())
        extra = sorted(configured_exceptions.keys() - profile_exceptions.keys())
        mismatched = sorted(
            family
            for family in profile_exceptions.keys() & configured_exceptions.keys()
            if profile_exceptions[family] != configured_exceptions[family]
        )
        raise RegistryError(
            "metric compatibility profile: high-cardinality coverage mismatch "
            f"missing={missing} extra={extra} mismatched={mismatched}"
        )


def _validate_span_name_patterns(
    groups: dict[str, GroupIR],
    local_attributes: dict[str, AttributeIR],
    upstream_extensions: dict[str, AttributeExtensionIR],
    upstream_attributes: Mapping[str, tuple[str, SnapshotAttribute]],
) -> None:
    prohibited_classes = {"content", "credential", "path", "evidence", "reason", "error"}
    for group in groups.values():
        if group.type != "span":
            continue
        if group.span_name_pattern is None or group.span_name_parts is None:
            raise RegistryError(f"span {group.id}: missing compiled name pattern")
        uses = {use.ref: use for use in group.resolved_uses}
        for part in group.span_name_parts:
            if part.kind == "literal":
                continue
            assert part.field is not None
            placeholder = part.field
            use = uses.get(placeholder)
            if use is None:
                raise RegistryError(f"span {group.id}: unresolved or transformed name placeholder {placeholder!r}")
            local = local_attributes.get(placeholder)
            extension = upstream_extensions.get(placeholder)
            if local is not None:
                field_class = local.field_class
                cardinality = local.cardinality
                string_only = local.field_type == "string"
            elif extension is not None:
                field_class = extension.field_class
                cardinality = extension.cardinality
                upstream = upstream_attributes.get(placeholder)
                string_only = upstream is not None and upstream[1].allowed_types == ("string",)
            else:
                raise RegistryError(f"span {group.id}: name placeholder has no privacy metadata")
            if (
                use.role != "attributes"
                or use.requirement_level != "required"
                or use.conditional is not None
                or not string_only
            ):
                raise RegistryError(
                    f"span {group.id}: name placeholder {placeholder!r} must resolve as an unconditional "
                    "required string attribute"
                )
            if cardinality == "high" or field_class in prohibited_classes:
                raise RegistryError(
                    f"span {group.id}: unsafe name placeholder {placeholder} "
                    f"class={field_class} cardinality={cardinality}"
                )


def _bounded_candidate_error(exc: Exception, reviewed_types: tuple[type[Exception], ...]) -> str:
    if not isinstance(exc, reviewed_types):
        return "unexpected candidate renderer failure"
    detail = " ".join(str(exc).split())
    if not detail:
        detail = type(exc).__name__
    return detail if len(detail) <= 512 else detail[:509] + "..."


def _expected_portable_output_paths(ir: RegistryIR) -> tuple[str, ...]:
    paths = list(PORTABLE_STATIC_OUTPUT_PATHS)
    for example in ir.examples:
        category = "valid" if example.valid else "invalid"
        paths.extend(
            (
                f"schemas/telemetry/generated/examples/{category}/{example.id}.json",
                f"schemas/telemetry/generated/otlp-fixtures/cases/{example.id}.json",
            )
        )
    if len(paths) != len(set(paths)):
        raise RegistryError("candidate telemetry output plan contains duplicate paths")
    return tuple(sorted(paths))


def _validate_portable_candidate_inventory(
    ir: RegistryIR,
    portable_renderer: Any,
    portable_outputs: Mapping[str, Any],
) -> tuple[str, ...]:
    """Validate the renderer's exact portable output inventory."""

    if not isinstance(portable_outputs, Mapping) or any(type(path) is not str for path in portable_outputs):
        raise RegistryError("candidate renderer output inventory is invalid")
    actual = tuple(sorted(portable_outputs))
    expected = _expected_portable_output_paths(ir)
    if actual != expected:
        raise RegistryError("candidate renderer output inventory is partial or substituted")
    if any(getattr(portable_outputs[path], "path", None) != path for path in actual):
        raise RegistryError("candidate renderer output path disagrees with its artifact")
    return expected


def _validate_rendered_v7_exporter_selection(
    ir: RegistryIR,
    portable_outputs: Mapping[str, Any],
) -> None:
    path = "schemas/telemetry/generated/compatibility/v7-exporter-selection.json"
    output = portable_outputs.get(path)
    payload = getattr(output, "payload", None)
    if type(payload) is not bytes or len(payload) > V7_EXPORTER_SELECTION_SCHEMA_MAX_BYTES:
        raise RegistryError("rendered v7 exporter selection payload is invalid")
    document = _parse_json_strict_bytes(Path(path), payload)
    expected = _v7_exporter_selection_document(
        ir.v7_exporter_selection,
        schema_version=ir.schema_version,
        registry_version=ir.registry_version,
        materialized_view_sha256=ir.materialized_view.typed_canonical_json_sha256,
    )
    if document != expected:
        raise RegistryError("rendered v7 exporter selection disagrees with compiler authority")
    errors = sorted(
        Draft202012Validator(_thaw_json(ir.v7_exporter_selection_schema)).iter_errors(document),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    )
    if errors:
        location = "/".join(str(part) for part in errors[0].absolute_path) or "$"
        raise RegistryError(f"rendered v7 exporter selection schema violation at {location}")


def render_outputs(ir: RegistryIR) -> dict[Path, bytes]:
    try:
        portable_renderer, go_renderer, coordinator = _load_candidate_renderers()
        index = portable_renderer.build_candidate_render_index(ir.materialized_view)
        portable_outputs = portable_renderer.render_candidate_artifacts_from_index(index)
        expected_portable_paths = _validate_portable_candidate_inventory(ir, portable_renderer, portable_outputs)
        _validate_rendered_v7_exporter_selection(ir, portable_outputs)
        go_render = go_renderer.render_go_candidate(index)
        if tuple(coordinator.EXACT_GO_OUTPUT_PATHS) != GO_CANDIDATE_OUTPUT_PATHS:
            raise RegistryError("generated Go coordinator output paths disagree with the compiler contract")
        go_preflight = coordinator.preflight_go_outputs(
            go_render.outputs,
            go_render.declaration_inventory,
            expected_declaration_keys=go_render.expected_declaration_keys,
            materialized_view_sha256=go_render.materialized_view_sha256,
            candidate_render_index_sha256=go_render.candidate_render_index_sha256,
            go_symbol_table_sha256=go_render.go_symbol_table_sha256,
        )
        if tuple(item.path for item in go_preflight.outputs) != GO_CANDIDATE_OUTPUT_PATHS:
            raise RegistryError("generated Go preflight did not return the exact ordered output set")
        if portable_renderer.CANDIDATE_AUTHORITY != GO_CANDIDATE_AUTHORITY:
            raise RegistryError("portable and Go candidate authority markers disagree")
    except RegistryError:
        raise
    except Exception as exc:
        reviewed_types = tuple(
            error_type
            for module, name in (
                (locals().get("portable_renderer"), "CandidateRenderError"),
                (locals().get("go_renderer"), "GoRenderError"),
                (locals().get("coordinator"), "GoOutputPreflightError"),
            )
            if module is not None and isinstance((error_type := getattr(module, name, None)), type)
        )
        raise RegistryError(
            f"candidate telemetry rendering failed: {_bounded_candidate_error(exc, reviewed_types)}"
        ) from exc

    # Every portable candidate above is built and validated. Only runtime and
    # release inputs become repository-owned artifacts; reports and fixture
    # corpora remain reproducible in-memory compiler products.
    repository_portable_paths = tuple(path for path in expected_portable_paths if _is_repository_output(path))
    artifacts: dict[Path, bytes] = {}
    for path, output in portable_outputs.items():
        if not _is_repository_output(path):
            continue
        normalized = Path(path)
        if normalized in artifacts:
            raise RegistryError(f"candidate renderer produced a duplicate output path: {path}")
        if type(output.payload) is not bytes:
            raise RegistryError(f"candidate renderer produced non-bytes output: {path}")
        artifacts[normalized] = output.payload
    for output in go_preflight.outputs:
        normalized = Path(output.path)
        if normalized in artifacts:
            raise RegistryError(f"candidate renderer produced a duplicate output path: {output.path}")
        artifacts[normalized] = output.payload
    expected_repository_paths = {
        *repository_portable_paths,
        *GO_CANDIDATE_OUTPUT_PATHS,
    }
    if {path.as_posix() for path in artifacts} != expected_repository_paths:
        raise RegistryError("candidate renderer repository output inventory is partial or substituted")
    return artifacts


def _physical_outputs(outputs: Mapping[Path, bytes]) -> dict[str, bytes]:
    logical = {path.as_posix(): payload for path, payload in outputs.items()}
    expected = {*runtime_assets.LOGICAL_TO_ENCODED, *GO_CANDIDATE_OUTPUT_PATHS}
    if set(logical) != expected or any(type(payload) is not bytes for payload in logical.values()):
        raise RegistryError("generated repository output inventory is partial or substituted")
    physical = {
        runtime_assets.LOGICAL_TO_ENCODED[path]: runtime_assets.canonical_gzip(logical[path])
        for path in runtime_assets.LOGICAL_TO_ENCODED
    }
    physical.update({path: logical[path] for path in GO_CANDIDATE_OUTPUT_PATHS})
    if set(physical) != REPOSITORY_PHYSICAL_OUTPUT_PATHS:
        raise RegistryError("generated physical output inventory is partial or substituted")
    return physical


def _repository_root(root: Path) -> Path:
    root = root.absolute()
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise RegistryError("repository root is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RegistryError("repository root must be a real directory")
    return root


def _safe_target(root: Path, relative: str, *, create_parents: bool) -> Path:
    target = root / relative
    current = root
    for part in PurePosixPath(relative).parts[:-1]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if not create_parents:
                return target
            try:
                current.mkdir(mode=0o755)
                metadata = current.lstat()
            except OSError as exc:
                raise RegistryError(f"cannot create generated output parent: {relative}") from exc
        except OSError as exc:
            raise RegistryError(f"cannot inspect generated output parent: {relative}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise RegistryError(f"generated output parent is not a real directory: {relative}")
    return target


def _target_metadata(root: Path, relative: str) -> tuple[Path, os.stat_result | None]:
    target = _safe_target(root, relative, create_parents=False)
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return target, None
    except OSError as exc:
        raise RegistryError(f"cannot inspect generated output: {relative}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RegistryError(f"generated output is not a regular file: {relative}")
    return target, metadata


def _existing_output_directory(root: Path, relative: str) -> Path | None:
    probe = _safe_target(root, f"{relative}/.inventory", create_parents=False)
    directory = probe.parent
    try:
        metadata = directory.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RegistryError(f"cannot inspect generated output directory: {relative}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RegistryError(f"generated output directory is not a real directory: {relative}")
    return directory


def _extra_outputs(root: Path) -> list[str]:
    extras: set[str] = set()
    internal = _existing_output_directory(root, "internal/observability")
    if internal is not None:
        for path in internal.glob("zz_generated_telemetry_*.go"):
            relative = path.relative_to(root).as_posix()
            if relative not in REPOSITORY_PHYSICAL_OUTPUT_PATHS:
                extras.add(relative)
    runtime_root = _existing_output_directory(root, runtime_assets.RUNTIME_ASSET_ROOT.as_posix())
    if runtime_root is not None:
        for path in runtime_root.rglob("*.gz"):
            relative = path.relative_to(root).as_posix()
            if relative not in REPOSITORY_PHYSICAL_OUTPUT_PATHS:
                extras.add(relative)
    for relative in RETIRED_REPOSITORY_OUTPUT_PATHS:
        _, metadata = _target_metadata(root, relative)
        if metadata is not None:
            extras.add(relative)
    return sorted(extras)


def _drift(root: Path, desired: Mapping[str, bytes]) -> list[str]:
    problems: list[str] = []
    for relative in sorted(desired):
        target, metadata = _target_metadata(root, relative)
        if metadata is None:
            problems.append(f"missing={relative}")
            continue
        try:
            payload = target.read_bytes()
        except OSError as exc:
            raise RegistryError(f"cannot read generated output: {relative}") from exc
        if payload != desired[relative]:
            problems.append(f"stale={relative}")
        if stat.S_IMODE(metadata.st_mode) != REPOSITORY_OUTPUT_MODE:
            problems.append(f"mode={relative}")
    problems.extend(f"extra={relative}" for relative in _extra_outputs(root))
    return problems


def check_outputs(root: Path, outputs: Mapping[Path, bytes]) -> None:
    root = _repository_root(root)
    desired = _physical_outputs(outputs)
    problems = _drift(root, desired)
    if problems:
        raise RegistryError(
            "generated output drift: "
            + "; ".join(problems)
            + "; run scripts/generate_telemetry_registry.py --write"
        )


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        # Windows does not permit opening directories through os.open. The
        # same-directory os.replace remains atomic; directory fsync is a
        # POSIX durability enhancement rather than a generation contract.
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(root: Path, relative: str, payload: bytes) -> None:
    target = _safe_target(root, relative, create_parents=True)
    _, metadata = _target_metadata(root, relative)
    if metadata is not None:
        try:
            if target.read_bytes() == payload and stat.S_IMODE(metadata.st_mode) == REPOSITORY_OUTPUT_MODE:
                return
        except OSError as exc:
            raise RegistryError(f"cannot read generated output: {relative}") from exc
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fchmod(stream.fileno(), REPOSITORY_OUTPUT_MODE)
            os.fsync(stream.fileno())
        _safe_target(root, relative, create_parents=False)
        os.replace(temporary, target)
        _sync_directory(target.parent)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _remove_retired_outputs(root: Path) -> None:
    for relative in sorted(RETIRED_REPOSITORY_OUTPUT_PATHS):
        target, metadata = _target_metadata(root, relative)
        if metadata is None:
            continue
        try:
            target.unlink()
            _sync_directory(target.parent)
        except OSError as exc:
            raise RegistryError(f"cannot remove retired generated output: {relative}") from exc


def write_outputs(root: Path, outputs: Mapping[Path, bytes]) -> None:
    root = _repository_root(root)
    desired = _physical_outputs(outputs)
    unknown = [
        relative
        for relative in _extra_outputs(root)
        if relative not in RETIRED_REPOSITORY_OUTPUT_PATHS
    ]
    if unknown:
        raise RegistryError(f"generated output drift: extra={unknown}")
    _remove_retired_outputs(root)
    for relative, payload in sorted(desired.items()):
        _atomic_write(root, relative, payload)
    check_outputs(root, outputs)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="write deterministic generated outputs")
    mode.add_argument("--check", action="store_true", help="fail when generated outputs drift")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args(argv)
    try:
        root = _repository_root(args.root)
        ir = compile_registry(root)
        outputs = render_outputs(ir)
        if args.write:
            write_outputs(root, outputs)
        else:
            check_outputs(root, outputs)
    except (RegistryError, OSError) as exc:
        print(f"telemetry registry generation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
