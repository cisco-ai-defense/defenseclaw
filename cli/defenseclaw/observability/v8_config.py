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

"""Strict, secret-safe Python validation for v8 observability sources.

The checked-in Draft 2020-12 schema is the source-format authority.  This
module performs the additional source-only semantic checks needed by Python
setup, validate, and reference surfaces, then exposes a deterministic masked
copy.  It does not expand an effective route graph, match records, resolve
secrets, perform DNS, or initialize exporters.  The Go v8 compiler remains the
sole owner of effective policy and the runtime router.

The Python/Go parity seam is intentionally small: catalog vocabulary, default
policy, destination capabilities, route/profile vocabulary, and semantic
source rejection.  Exact event-name/action registry validation and effective
provenance remain Go-owned until those registries are emitted as shared
generated artifacts rather than copied into a second implementation.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import math
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import yaml
from yaml.composer import ComposerError
from yaml.constructor import ConstructorError
from yaml.events import (
    AliasEvent,
    MappingEndEvent,
    MappingStartEvent,
    ScalarEvent,
    SequenceEndEvent,
    SequenceStartEvent,
)
from yaml.nodes import MappingNode

from defenseclaw.observability.detector_catalog_v1 import (
    DETECTOR_GROUPS as CATALOG_DETECTOR_GROUPS,
)

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_YAML_NODES = 65_536
MAX_YAML_DEPTH = 32
MAX_DESTINATIONS = 64
MAX_ROUTES_PER_DESTINATION = 256
MAX_ROUTES_TOTAL = 4_096
MAX_PROFILES = 128
MAX_MAPPING_ENTRIES = 1_024
MAX_RESOURCE_ATTRIBUTES = 64
MAX_RESOURCE_KEY_BYTES = 128
MAX_RESOURCE_VALUE_BYTES = 1_024
MAX_RESOURCE_TOTAL_BYTES = 16 * 1_024

BUCKETS = (
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
SIGNALS = ("logs", "traces", "metrics")
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
DETECTOR_GROUPS = ("pii", "credentials", "secrets")
if frozenset(DETECTOR_GROUPS) != frozenset(CATALOG_DETECTOR_GROUPS):
    raise RuntimeError("Python v8 detector vocabulary drifted from detector catalog v1")
FIELD_CLASSES = (
    "metadata",
    "identifier",
    "content",
    "reason",
    "evidence",
    "error",
    "path",
    "credential",
)
FIELD_MODES = ("preserve", "detect", "whole", "hash", "remove")
BUILT_IN_PROFILES = ("none", "sensitive", "content", "strict", "legacy-v7")
ROUTE_ACTIONS = ("send", "drop")
SELECTOR_FIELDS = ("buckets", "sources", "connectors", "actions", "event_names", "min_severity")
DESTINATION_CAPABILITIES: dict[str, tuple[str, ...]] = {
    "jsonl": ("logs",),
    "console": ("logs",),
    "prometheus": ("metrics",),
    "splunk_hec": ("logs",),
    "http_jsonl": ("logs",),
    "otlp": SIGNALS,
}
DESTINATION_BATCH_MODES = {
    "jsonl": "queue",
    "console": "queue",
    "prometheus": "none",
    "splunk_hec": "push",
    "http_jsonl": "push",
    "otlp": "push",
}
QUEUE_DEFAULTS = {
    "max_queue_size": 2_048,
    "max_queue_bytes": 67_108_864,
}
PUSH_BATCH_DEFAULTS = {
    "max_export_batch_size": 512,
    "max_export_batch_bytes": 8_388_608,
    "scheduled_delay_ms": 5_000,
}
QUEUE_BOUNDS = {
    "max_queue_size": (1, 65_536),
    "max_queue_bytes": (4_198_400, 268_435_456),
}
PUSH_BATCH_BOUNDS = {
    "max_export_batch_size": (1, 8_192),
    "max_export_batch_bytes": (4_263_936, 67_108_864),
    "scheduled_delay_ms": (1, 600_000),
}

_TRACE_LIMIT_BOUNDS = {
    "max_attributes_per_span": (32, 256),
    "max_events_per_span": (1, 128),
    "max_links_per_span": (1, 64),
    "max_attributes_per_event": (4, 64),
    "max_attribute_value_bytes": (256, 65_536),
    "max_projected_span_bytes": (4_096, 1_048_576),
    "max_stacktrace_bytes": (256, 131_072),
    "max_message_items": (1, 512),
}
_TRACE_LIMIT_DEFAULTS = {
    "max_attributes_per_span": 128,
    "max_events_per_span": 64,
    "max_links_per_span": 32,
    "max_attributes_per_event": 32,
    "max_attribute_value_bytes": 16_384,
    "max_projected_span_bytes": 262_144,
    "max_stacktrace_bytes": 32_768,
    "max_message_items": 128,
}
_STABLE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_RESOURCE_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_OTLP_PROTOCOLS = frozenset(("grpc", "grpc/protobuf", "http", "http/protobuf"))
_RESERVED_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "240.0.0.0/4",
        "64:ff9b:1::/48",
        "2001:2::/48",
        "2001:10::/28",
        "2001:db8::/32",
    )
)

RESERVED_RESOURCE_ATTRIBUTE_KEYS = frozenset(
    {
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
        "defenseclaw.claw.home_dir",
        "defenseclaw.gateway.host",
        "defenseclaw.gateway.port",
        "discovery.source",
        "deployment.environment",
        "deployment.mode",
        "defenseclaw.device.id",
        "defenseclaw.preset",
        "defenseclaw.preset_name",
        "telemetry.sdk.name",
        "telemetry.sdk.language",
        "telemetry.sdk.version",
    }
)
CONFIGURABLE_CORE_RESOURCE_ATTRIBUTE_KEYS = frozenset(
    {
        "service.name",
        "deployment.environment.name",
        "deployment.environment",
        "tenant.id",
        "workspace.id",
    }
)
_RESOURCE_ALIAS_PAIRS = (
    ("deployment.environment.name", "deployment.environment"),
    ("defenseclaw.deployment.mode", "deployment.mode"),
    ("defenseclaw.device.public_key_fingerprint", "defenseclaw.device.id"),
)
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
ENDPOINT_HOST_PUBLIC = "public"
ENDPOINT_HOST_LOCALHOST = "localhost"
ENDPOINT_HOST_PRIVATE = "private"
ENDPOINT_HOST_CGNAT = "cgnat"
ENDPOINT_HOST_METADATA = "metadata"
ENDPOINT_HOST_PROHIBITED = "prohibited"
ENDPOINT_HOST_INVALID = "invalid"
_METADATA_ADDRESSES = frozenset(
    (
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "168.63.129.16",
        "fd00:ec2::254",
    )
)
_PRIVATE_UPSTREAM_METADATA_ADDRESSES = frozenset(
    ipaddress.ip_address(value)
    for value in (
        "169.254.169.254",
        "169.254.170.2",
        "fd00:ec2::254",
    )
)
_METADATA_HOSTS = frozenset(
    (
        "metadata.google.internal",
        "metadata.goog",
        "metadata.azure.internal",
        "instance-data.ec2.internal",
        "task-metadata-endpoint",
    )
)
_SECRET_FIELD_NAMES = frozenset(
    (
        "api_key",
        "token",
        "password",
        "passwd",
        "secret",
        "virustotal_api_key",
        "ca_cert_pem",
    )
)
_HEADER_MAP_FIELD_NAMES = frozenset(("headers", "extra_headers"))


class V8ConfigError(ValueError):
    """A source-validation error whose message never contains source values."""

    def __init__(self, source_name: str, path: str, keyword: str, corrective_action: str) -> None:
        self.source_name = source_name
        self.path = path or "$"
        self.keyword = keyword
        self.corrective_action = corrective_action
        super().__init__(f"{source_name}: invalid v8 configuration at {self.path} ({keyword}); {corrective_action}")


@dataclass(frozen=True)
class ValidatedV8Config:
    """Detached schema-valid, deterministic masked source projection."""

    source_name: str
    _masked: dict[str, Any] = field(repr=False)

    @property
    def source(self) -> dict[str, Any]:
        """Return the display-safe source; raw source values are not retained."""

        return copy.deepcopy(self._masked)

    @property
    def masked(self) -> dict[str, Any]:
        return copy.deepcopy(self._masked)

    @property
    def parity_contract(self) -> dict[str, Any]:
        """Return the small versioned vocabulary shared with the Go compiler."""

        return observability_v8_parity_contract()

    def masked_json(self) -> str:
        return json.dumps(self._masked, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def digest(self) -> str:
        return hashlib.sha256(self.masked_json().encode("utf-8")).hexdigest()


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader variant that rejects aliases, merge keys, and duplicates."""

    _ALLOWED_TAGS = frozenset(
        (
            "tag:yaml.org,2002:map",
            "tag:yaml.org,2002:seq",
            "tag:yaml.org,2002:str",
            "tag:yaml.org,2002:null",
            "tag:yaml.org,2002:bool",
            "tag:yaml.org,2002:int",
            "tag:yaml.org,2002:float",
            "tag:yaml.org,2002:timestamp",
            "tag:yaml.org,2002:binary",
        )
    )

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(AliasEvent):
            event = self.peek_event()
            raise ComposerError(None, None, "aliases are not allowed", event.start_mark)
        return super().compose_node(parent, index)

    def construct_object(self, node: Any, deep: bool = False) -> Any:
        if node.tag not in self._ALLOWED_TAGS:
            raise ConstructorError(None, None, "custom YAML tags are not allowed", node.start_mark)
        return super().construct_object(node, deep=deep)

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        if not isinstance(node, MappingNode):
            raise ConstructorError(None, None, "expected a mapping", node.start_mark)
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge" or key_node.value == "<<":
                raise ConstructorError(None, None, "merge keys are not allowed", key_node.start_mark)
            if key_node.tag != "tag:yaml.org,2002:str":
                raise ConstructorError(None, None, "mapping keys must be strings", key_node.start_mark)
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ConstructorError(None, None, "mapping keys must be strings", key_node.start_mark)
            try:
                duplicate = key in result
            except TypeError as exc:
                raise ConstructorError(None, None, "mapping keys must be scalar", key_node.start_mark) from exc
            if duplicate:
                raise ConstructorError(None, None, "duplicate mapping key", key_node.start_mark)
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _construct_text_scalar(loader: _StrictLoader, node: Any) -> str:
    # Go's v8 projection intentionally represents timestamp and binary-tagged
    # scalars by their source text before JSON-schema validation.
    return node.value


_StrictLoader.add_constructor("tag:yaml.org,2002:timestamp", _construct_text_scalar)
_StrictLoader.add_constructor("tag:yaml.org,2002:binary", _construct_text_scalar)


def load_validate_v8(data: str | bytes | Mapping[str, Any], *, source_name: str = "config.yaml") -> ValidatedV8Config:
    """Parse and validate one exact-v8 source without reading secrets or network."""

    document = _parse_source(data, source_name)
    _validate_resource_attribute_encoding_and_collisions(document, source_name)
    _validate_schema(document, source_name)
    _validate_semantics(document, source_name)
    return ValidatedV8Config(source_name, _masked_copy(document))


def validate_v8_source(data: str | bytes | Mapping[str, Any], *, source_name: str = "config.yaml") -> dict[str, Any]:
    """Return a detached, validated, display-safe source mapping."""

    return load_validate_v8(data, source_name=source_name).source


def observability_v8_parity_contract() -> dict[str, Any]:
    """Return source vocabulary/default facts pinned against the canonical schema."""

    # Loading the validator also asserts that duplicated constants have not
    # drifted from their canonical schema enums.
    _schema_validator()
    return {
        "config_version": 8,
        "bucket_catalog_version": 1,
        "buckets": list(BUCKETS),
        "signals": list(SIGNALS),
        "severities": list(SEVERITIES),
        "catalog_defaults": {
            "collect": {"logs": True, "traces": True, "metrics": True},
            "redaction_profile": "none",
            "local_retention_days": 90,
            "trace_sampler": "parentbased_always_on",
            "metric_export_interval_seconds": 60,
            "metric_temporality": "delta",
        },
        "destination_capabilities": {name: list(signals) for name, signals in DESTINATION_CAPABILITIES.items()},
        "destination_batch_modes": dict(DESTINATION_BATCH_MODES),
        "galileo_capabilities": ["traces"],
        "queue_defaults": dict(QUEUE_DEFAULTS),
        "push_batch_defaults": dict(PUSH_BATCH_DEFAULTS),
        "queue_bounds": {name: list(bounds) for name, bounds in QUEUE_BOUNDS.items()},
        "push_batch_bounds": {name: list(bounds) for name, bounds in PUSH_BATCH_BOUNDS.items()},
        "profiles": list(BUILT_IN_PROFILES),
        "detector_groups": list(DETECTOR_GROUPS),
        "field_classes": list(FIELD_CLASSES),
        "field_modes": list(FIELD_MODES),
        "route_actions": list(ROUTE_ACTIONS),
        "selector_fields": list(SELECTOR_FIELDS),
    }


def _parse_source(data: str | bytes | Mapping[str, Any], source_name: str) -> dict[str, Any]:
    if isinstance(data, Mapping):
        _preflight_python_structure(data, source_name)
        try:
            document = copy.deepcopy(dict(data))
        except (RecursionError, OverflowError):
            raise V8ConfigError(
                source_name,
                "$",
                "max-depth",
                "reduce nesting depth below 33 levels",
            ) from None
    else:
        try:
            raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        except UnicodeEncodeError:
            raise V8ConfigError(
                source_name,
                "$",
                "utf-8",
                "replace invalid Unicode surrogate code points with valid UTF-8 text",
            ) from None
        if len(raw) > MAX_SOURCE_BYTES:
            raise V8ConfigError(source_name, "$", "max-source-bytes", "reduce the source below 4 MiB")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise V8ConfigError(source_name, "$", "utf-8", "save the configuration as UTF-8") from exc
        _preflight_yaml_structure(text, source_name)
        try:
            document = yaml.load(text, Loader=_StrictLoader)
        except (RecursionError, OverflowError):
            raise V8ConfigError(
                source_name,
                "$",
                "max-depth",
                "reduce nesting depth below 33 levels",
            ) from None
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            path = f"$ (line {mark.line + 1}, column {mark.column + 1})" if mark is not None else "$"
            raise V8ConfigError(
                source_name,
                path,
                "yaml",
                "remove duplicate keys, aliases, merge keys, or malformed YAML",
            ) from exc
    if not isinstance(document, dict):
        raise V8ConfigError(source_name, "$", "type", "use one YAML mapping as the document root")
    try:
        _validate_preflight_values(document, source_name)
        nodes, depth = _shape(document)
    except (RecursionError, OverflowError):
        raise V8ConfigError(
            source_name,
            "$",
            "max-depth",
            "reduce nesting depth below 33 levels",
        ) from None
    if nodes > MAX_YAML_NODES:
        raise V8ConfigError(source_name, "$", "max-nodes", "reduce the configuration below 65536 nodes")
    if depth > MAX_YAML_DEPTH:
        raise V8ConfigError(source_name, "$", "max-depth", "reduce nesting depth below 33 levels")
    return document


def _preflight_python_structure(value: Any, source_name: str) -> None:
    """Bound already-materialized mapping input before recursive copy/validation."""

    nodes = 0
    seen_containers: set[int] = set()
    pending: list[tuple[Any, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > MAX_YAML_NODES:
            raise V8ConfigError(source_name, "$", "max-nodes", "reduce the configuration below 65536 nodes")
        if not isinstance(current, (Mapping, list)):
            continue
        if depth > MAX_YAML_DEPTH:
            raise V8ConfigError(source_name, "$", "max-depth", "reduce nesting depth below 33 levels")
        identity = id(current)
        if identity in seen_containers:
            raise V8ConfigError(source_name, "$", "cycle", "remove cyclic container references")
        seen_containers.add(identity)
        if isinstance(current, Mapping):
            if len(current) > MAX_MAPPING_ENTRIES:
                raise V8ConfigError(
                    source_name,
                    "$",
                    "max-mapping-entries",
                    "reduce every mapping to 1024 entries or fewer",
                )
            nodes += len(current)  # mapping keys are separate YAML scalar nodes
            children = current.values()
        else:
            children = current
        for child in children:
            child_depth = depth + 1 if isinstance(child, (Mapping, list)) else depth
            pending.append((child, child_depth))


def _preflight_yaml_structure(text: str, source_name: str, *, reject_aliases: bool = True) -> None:
    """Enforce YAML node, collection-depth, and mapping limits before construction."""

    nodes = 0
    frames: list[list[int | bool]] = []

    def record_parent_child() -> None:
        if not frames or frames[-1][0] is not True:
            return
        frame = frames[-1]
        if frame[1] is True:
            frame[2] = int(frame[2]) + 1
            if int(frame[2]) > MAX_MAPPING_ENTRIES:
                raise V8ConfigError(
                    source_name,
                    "$",
                    "max-mapping-entries",
                    "reduce every mapping to 1024 entries or fewer",
                )
        frame[1] = frame[1] is not True

    try:
        for event in yaml.parse(text, Loader=_StrictLoader):
            if reject_aliases and isinstance(event, AliasEvent):
                raise V8ConfigError(
                    source_name,
                    "$",
                    "yaml",
                    "remove duplicate keys, aliases, merge keys, or malformed YAML",
                )
            if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
                record_parent_child()
                nodes += 1
                frames.append([isinstance(event, MappingStartEvent), True, 0])
                if len(frames) > MAX_YAML_DEPTH:
                    raise V8ConfigError(
                        source_name,
                        "$",
                        "max-depth",
                        "reduce nesting depth below 33 levels",
                    )
            elif isinstance(event, (MappingEndEvent, SequenceEndEvent)):
                frames.pop()
            elif isinstance(event, ScalarEvent):
                record_parent_child()
                nodes += 1
            if nodes > MAX_YAML_NODES:
                raise V8ConfigError(
                    source_name,
                    "$",
                    "max-nodes",
                    "reduce the configuration below 65536 nodes",
                )
    except V8ConfigError:
        raise
    except (yaml.YAMLError, RecursionError, OverflowError) as exc:
        mark = getattr(exc, "problem_mark", None)
        path = f"$ (line {mark.line + 1}, column {mark.column + 1})" if mark is not None else "$"
        raise V8ConfigError(
            source_name,
            path,
            "yaml",
            "remove duplicate keys, aliases, merge keys, malformed YAML, or excessive nesting",
        ) from None


def _shape(value: Any, depth: int = 1) -> tuple[int, int]:
    nodes = 1
    maximum = depth
    if isinstance(value, dict):
        nodes += len(value)  # Each YAML mapping key is a separately counted scalar node.
        children: Any = value.values()
    elif isinstance(value, list):
        children = value
    else:
        children = ()
    for child in children:
        child_depth_value = depth + 1 if isinstance(child, (dict, list)) else depth
        child_nodes, child_depth = _shape(child, child_depth_value)
        nodes += child_nodes
        maximum = max(maximum, child_depth)
    return nodes, maximum


def _validate_preflight_values(value: Any, source_name: str, path: str = "$") -> None:
    if isinstance(value, dict):
        if len(value) > MAX_MAPPING_ENTRIES:
            raise V8ConfigError(
                source_name,
                path,
                "max-mapping-entries",
                "reduce this mapping to 1024 entries or fewer",
            )
        for key, child in value.items():
            if not isinstance(key, str):
                raise V8ConfigError(source_name, path, "mapping-key", "use string mapping keys only")
            _validate_utf8_text(key, source_name, path)
            child_path = f"{path}.{key}"
            _validate_preflight_values(child, source_name, child_path)
        if path == "$":
            version = value.get("config_version")
            if type(version) is not int or version != 8:
                raise V8ConfigError(
                    source_name,
                    "$.config_version",
                    "exact-version",
                    "use the integer config_version: 8 after running defenseclaw upgrade",
                )
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_preflight_values(child, source_name, f"{path}[{index}]")
        return
    if isinstance(value, str):
        _validate_utf8_text(value, source_name, path)
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise V8ConfigError(
            source_name,
            path,
            "finite-number",
            "replace NaN or infinity with a finite number",
        )


def _validate_utf8_text(value: str, source_name: str, path: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise V8ConfigError(
            source_name,
            path,
            "utf-8",
            "replace invalid Unicode surrogate code points with valid UTF-8 text",
        ) from None


@lru_cache(maxsize=1)
def _schema_validator() -> Any:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:  # pragma: no cover - integration guard for minimal wheels
        raise RuntimeError("v8 config validation requires the existing jsonschema dependency") from exc
    packaged = resources.files("defenseclaw").joinpath("_data", "config", "v8", "defenseclaw-config.schema.json")
    try:
        with packaged.open("r", encoding="utf-8") as stream:
            schema = json.load(stream)
    except FileNotFoundError:
        root = Path(__file__).resolve().parents[3]
        schema_path = root / "schemas" / "config" / "v8" / "defenseclaw-config.schema.json"
        with schema_path.open(encoding="utf-8") as stream:
            schema = json.load(stream)
    Draft202012Validator.check_schema(schema)
    _assert_schema_parity(schema)
    return Draft202012Validator(schema)


def _assert_schema_parity(schema: dict[str, Any]) -> None:
    defs = schema["$defs"]
    expected = {
        "bucketName": BUCKETS,
        "severity": SEVERITIES,
        "fieldClassMode": FIELD_MODES,
    }
    for definition, values in expected.items():
        if tuple(defs[definition]["enum"]) != values:
            raise RuntimeError(f"Python v8 vocabulary drifted from $defs.{definition}")
    profile_values = tuple(defs["profileName"]["anyOf"][0]["enum"])
    if profile_values != BUILT_IN_PROFILES:
        raise RuntimeError("Python v8 profile vocabulary drifted from $defs.profileName")
    detector_values = tuple(defs["customRedactionProfile"]["properties"]["detectors"]["items"]["enum"])
    if detector_values != DETECTOR_GROUPS:
        raise RuntimeError("Python v8 detector vocabulary drifted from $defs.customRedactionProfile")
    if tuple(defs["signals"]["items"]["enum"]) != SIGNALS:
        raise RuntimeError("Python v8 signal vocabulary drifted from $defs.signals")
    if tuple(defs["fieldClassModes"]["properties"]) != FIELD_CLASSES:
        raise RuntimeError("Python v8 field-class vocabulary drifted from $defs.fieldClassModes")
    if tuple(defs["routeAction"]["enum"]) != ROUTE_ACTIONS:
        raise RuntimeError("Python v8 route actions drifted from $defs.routeAction")
    if tuple(defs["selector"]["properties"]) != SELECTOR_FIELDS:
        raise RuntimeError("Python v8 selector vocabulary drifted from $defs.selector")
    resource_attributes = defs["resource"]["properties"]["attributes"]
    resource_names = resource_attributes["propertyNames"]
    resource_values = resource_attributes["additionalProperties"]
    if (
        resource_attributes.get("maxProperties") != MAX_RESOURCE_ATTRIBUTES
        or resource_names.get("maxLength") != MAX_RESOURCE_KEY_BYTES
        or resource_names.get("pattern") != _RESOURCE_KEY.pattern
        or resource_values.get("minLength") != 1
        or resource_values.get("maxLength") != MAX_RESOURCE_VALUE_BYTES
    ):
        raise RuntimeError("Python v8 resource attribute bounds drifted from $defs.resource")
    queue_properties = defs["queueBatch"]["properties"]
    push_properties = defs["batch"]["properties"]
    for name, expected in QUEUE_DEFAULTS.items():
        if queue_properties[name]["default"] != expected or push_properties[name]["default"] != expected:
            raise RuntimeError(f"Python v8 queue default drifted from $defs.batch.{name}")
    for name, (minimum, maximum) in QUEUE_BOUNDS.items():
        for properties in (queue_properties, push_properties):
            if properties[name]["minimum"] != minimum or properties[name]["maximum"] != maximum:
                raise RuntimeError(f"Python v8 queue bounds drifted from $defs.batch.{name}")
    for name, expected in PUSH_BATCH_DEFAULTS.items():
        if push_properties[name]["default"] != expected:
            raise RuntimeError(f"Python v8 push default drifted from $defs.batch.{name}")
    for name, (minimum, maximum) in PUSH_BATCH_BOUNDS.items():
        if push_properties[name]["minimum"] != minimum or push_properties[name]["maximum"] != maximum:
            raise RuntimeError(f"Python v8 push bounds drifted from $defs.batch.{name}")
    destination_defs = {
        "jsonlDestination": "jsonl",
        "consoleDestination": "console",
        "prometheusDestination": "prometheus",
        "splunkHECDestination": "splunk_hec",
        "httpJSONLDestination": "http_jsonl",
        "otlpDestination": "otlp",
    }
    schema_kinds = tuple(defs[name]["properties"]["kind"]["const"] for name in destination_defs)
    if schema_kinds != tuple(DESTINATION_CAPABILITIES):
        raise RuntimeError("Python v8 destination kinds drifted from the canonical schema")
    for definition, kind in destination_defs.items():
        properties = defs[definition]["properties"]
        mode = DESTINATION_BATCH_MODES[kind]
        expected_ref = {"queue": "#/$defs/queueBatch", "push": "#/$defs/batch"}.get(mode)
        actual_ref = properties.get("batch", {}).get("$ref")
        if actual_ref != expected_ref:
            raise RuntimeError(f"Python v8 destination batch mode drifted for {kind}")
    default_checks = (
        (defs["collectPolicy"]["properties"]["logs"]["default"], True),
        (defs["collectPolicy"]["properties"]["traces"]["default"], True),
        (defs["collectPolicy"]["properties"]["metrics"]["default"], True),
        (defs["tracePolicy"]["properties"]["sampler"]["default"], "parentbased_always_on"),
        (defs["metricPolicy"]["properties"]["export_interval_seconds"]["default"], 60),
        (defs["metricPolicy"]["properties"]["temporality"]["default"], "delta"),
        (defs["localStore"]["properties"]["retention_days"]["default"], 90),
    )
    if any(actual != expected for actual, expected in default_checks):
        raise RuntimeError("Python v8 default policy drifted from the canonical schema")


def _validate_schema(document: dict[str, Any], source_name: str) -> None:
    errors = sorted(
        _schema_validator().iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if not errors:
        return
    error = errors[0]
    path = _json_path(tuple(error.absolute_path))
    keyword = str(error.validator or "schema")
    action = {
        "additionalProperties": "remove unsupported or legacy fields and run defenseclaw upgrade",
        "required": "add the required field shown by the v8 reference",
        "const": "use the exact v8 value from the canonical reference",
        "enum": "choose a value from the canonical v8 vocabulary",
        "oneOf": "use exactly one supported v8 source shape",
        "type": "use the value type documented by the canonical v8 schema",
    }.get(keyword, "correct the field using the canonical v8 schema and reference")
    raise V8ConfigError(source_name, path, keyword, action)


def _json_path(parts: tuple[Any, ...]) -> str:
    result = "$"
    for part in parts:
        result += f"[{part}]" if isinstance(part, int) else f".{part}"
    return result


def _semantic_error(source_name: str, path: str, action: str) -> None:
    raise V8ConfigError(source_name, f"$.{path}", "semantic", action)


def _validate_semantics(document: dict[str, Any], source_name: str) -> None:
    _validate_private_upstream_allowlist(document.get("guardrail") or {}, source_name)
    observability = document.get("observability") or {}
    profiles = observability.get("redaction_profiles", {})
    _validate_profiles(profiles, source_name)
    _validate_profile_references(observability, set(BUILT_IN_PROFILES) | set(profiles), source_name)
    _validate_resource_attributes(observability.get("resource", {}).get("attributes", {}), source_name)
    _validate_trace_policy(observability.get("trace_policy", {}), source_name)

    destinations = observability.get("destinations", [])
    if len(destinations) > MAX_DESTINATIONS:
        _semantic_error(source_name, "observability.destinations", "configure no more than 64 destinations")
    names: set[str] = {"local-sqlite"}
    route_total = 0
    for index, destination in enumerate(destinations):
        path = f"observability.destinations[{index}]"
        if destination["name"] in names:
            _semantic_error(source_name, f"{path}.name", "use a unique non-reserved destination name")
        names.add(destination["name"])
        routes = destination.get("routes", [])
        route_total += len(routes)
        if route_total > MAX_ROUTES_TOTAL:
            _semantic_error(source_name, "observability.destinations.routes", "configure no more than 4096 routes")
        if len(routes) > MAX_ROUTES_PER_DESTINATION:
            _semantic_error(source_name, f"{path}.routes", "configure no more than 256 routes")
        route_names: set[str] = set()
        for route_index, route in enumerate(routes):
            if route["name"] in route_names:
                _semantic_error(
                    source_name,
                    f"{path}.routes[{route_index}].name",
                    "use a unique route name within the destination",
                )
            route_names.add(route["name"])
        _validate_destination(destination, path, source_name)


def _validate_private_upstream_allowlist(guardrail: dict[str, Any], source_name: str) -> None:
    """Mirror the Go guardrail allowlist's source validation.

    The allowlist permits any otherwise valid address, including RFC 1918,
    ULA, public, and CGNAT space.  Only address classes that the runtime can
    never exempt are rejected here.  IPv4-mapped IPv6 values are normalized
    before classification, matching ``net.IP.To4`` in the Go validator.
    """

    for index, raw in enumerate(guardrail.get("allow_private_upstreams", [])):
        path = f"guardrail.allow_private_upstreams[{index}]"
        value = raw.strip()
        if not value:
            # Go deliberately ignores empty entries after trimming. The
            # runtime config loader removes them before constructing the
            # effective allowlist.
            continue
        if "/" in value:
            _semantic_error(source_name, path, "specify one literal IP address, not a CIDR")
        # Go's net.ParseIP does not accept scoped IPv6 literals.
        if "%" in value:
            _semantic_error(source_name, path, "use a valid literal IP address without a scope identifier")
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            _semantic_error(source_name, path, "use a valid literal IP address")
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if address in _PRIVATE_UPSTREAM_METADATA_ADDRESSES:
            _semantic_error(source_name, path, "do not allowlist a cloud metadata address")
        if address.is_loopback:
            _semantic_error(source_name, path, "do not allowlist a loopback address")
        if address.is_multicast or address.is_unspecified:
            _semantic_error(source_name, path, "use a unicast, specified upstream address")
        if address.is_link_local:
            _semantic_error(source_name, path, "do not allowlist a link-local address")


def _validate_profile_references(observability: dict[str, Any], known: set[str], source_name: str) -> None:
    defaults = observability.get("defaults", {})
    if defaults.get("redaction_profile", "none") not in known:
        _semantic_error(
            source_name,
            "observability.defaults.redaction_profile",
            "select a built-in or defined custom profile",
        )
    for bucket, policy in observability.get("buckets", {}).items():
        if "redaction_profile" in policy and policy["redaction_profile"] not in known:
            _semantic_error(
                source_name,
                f"observability.buckets.{bucket}.redaction_profile",
                "select a built-in or defined custom profile",
            )
    for index, destination in enumerate(observability.get("destinations", [])):
        if "send" in destination:
            candidates = (("send", destination["send"]),)
        else:
            candidates = tuple(
                (f"routes[{route_index}]", route) for route_index, route in enumerate(destination.get("routes", []))
            )
        for suffix, policy in candidates:
            if "redaction_profile" in policy and policy["redaction_profile"] not in known:
                _semantic_error(
                    source_name,
                    f"observability.destinations[{index}].{suffix}.redaction_profile",
                    "select a built-in or defined custom profile",
                )


def _validate_profiles(profiles: dict[str, Any], source_name: str) -> None:
    if len(profiles) > MAX_PROFILES:
        _semantic_error(source_name, "observability.redaction_profiles", "configure no more than 128 profiles")
    builtins = _built_in_field_modes()
    for name, source in profiles.items():
        base_modes = builtins[source["extends"]]
        overrides = source.get("field_classes", {})
        inherited = dict(base_modes)
        inherited.update(overrides)
        detectors = source.get("detectors", DETECTOR_GROUPS)
        if "detectors" in source and not detectors:
            _semantic_error(
                source_name,
                f"observability.redaction_profiles.{name}.detectors",
                "select at least one detector group",
            )
        for field_class, mode in inherited.items():
            field_path = f"observability.redaction_profiles.{name}.field_classes.{field_class}"
            if mode == "preserve" and field_class not in ("metadata", "identifier"):
                _semantic_error(source_name, field_path, "use a transformation at least as strong as the base profile")
            if field_class == "credential" and mode not in ("remove", "whole"):
                _semantic_error(source_name, field_path, "use remove or whole for credentials")
            if mode == "detect" and not detectors:
                _semantic_error(source_name, field_path, "configure a detector group for detect mode")


def _validate_trace_policy(policy: dict[str, Any], source_name: str) -> None:
    limits = dict(_TRACE_LIMIT_DEFAULTS)
    limits.update(policy.get("limits", {}))
    for name, (minimum, maximum) in _TRACE_LIMIT_BOUNDS.items():
        if not minimum <= limits[name] <= maximum:
            _semantic_error(
                source_name,
                f"observability.trace_policy.limits.{name}",
                f"use a value from {minimum} through {maximum}",
            )


def _validate_resource_attributes(attributes: dict[str, str], source_name: str) -> None:
    if len(attributes) > MAX_RESOURCE_ATTRIBUTES:
        _semantic_error(
            source_name,
            "observability.resource.attributes",
            "configure no more than 64 resource attributes",
        )
    for canonical, legacy in _RESOURCE_ALIAS_PAIRS:
        if canonical in attributes and legacy in attributes and attributes[canonical] != attributes[legacy]:
            _semantic_error(
                source_name,
                "observability.resource.attributes",
                "remove conflicting canonical and legacy alias spellings",
            )
    total_bytes = 0
    for name in sorted(attributes, key=lambda candidate: candidate.encode("utf-8")):
        value = attributes[name]
        name_bytes = len(name.encode("utf-8"))
        value_bytes = len(value.encode("utf-8"))
        if name_bytes > MAX_RESOURCE_KEY_BYTES or _RESOURCE_KEY.fullmatch(name) is None:
            _semantic_error(
                source_name,
                "observability.resource.attributes",
                "use ASCII attribute names matching ^[A-Za-z][A-Za-z0-9_.-]{0,127}$",
            )
        if not 1 <= value_bytes <= MAX_RESOURCE_VALUE_BYTES:
            _semantic_error(
                source_name,
                f"observability.resource.attributes.{name}",
                "use a value containing 1 through 1024 UTF-8 bytes",
            )
        if not value.strip():
            _semantic_error(
                source_name,
                f"observability.resource.attributes.{name}",
                "use a nonblank resource attribute value",
            )
        if any(unicodedata.category(character) == "Cc" for character in value):
            _semantic_error(
                source_name,
                f"observability.resource.attributes.{name}",
                "remove control characters from the resource attribute value",
            )
        normalized = re.sub(r"[-_/]", ".", name.lower())
        segments = normalized.split(".")
        if (
            any(
                segment
                in {
                    "authorization",
                    "credential",
                    "credentials",
                    "password",
                    "passwd",
                    "secret",
                    "token",
                    "apikey",
                    "cookie",
                }
                for segment in segments
            )
            or "api.key" in normalized
        ):
            _semantic_error(
                source_name,
                f"observability.resource.attributes.{name}",
                "remove secret-bearing resource attributes",
            )
        if any(
            segment in {"cwd", "dir", "directory", "file", "filepath", "home", "path", "workdir"}
            for segment in segments
        ):
            _semantic_error(
                source_name,
                f"observability.resource.attributes.{name}",
                "remove filesystem and home-directory paths from resource attributes",
            )
        trimmed = value.strip()
        lower = trimmed.lower()
        if (
            trimmed.startswith(("/", "~/", "\\\\"))
            or lower.startswith("file://")
            or re.match(r"^[A-Za-z]:[\\/]", trimmed)
        ):
            _semantic_error(
                source_name,
                f"observability.resource.attributes.{name}",
                "remove filesystem and home-directory paths from resource attributes",
            )
        upper = trimmed.upper()
        has_inline_credentials = _resource_value_has_inline_credentials(trimmed)
        if (
            ("PRIVATE KEY" in upper and "-----BEGIN" in upper)
            or upper.startswith(("BEARER ", "BASIC "))
            or has_inline_credentials
        ):
            _semantic_error(
                source_name,
                f"observability.resource.attributes.{name}",
                "remove credential material from resource attributes",
            )
        if name in RESERVED_RESOURCE_ATTRIBUTE_KEYS and name not in CONFIGURABLE_CORE_RESOURCE_ATTRIBUTE_KEYS:
            _semantic_error(
                source_name,
                f"observability.resource.attributes.{name}",
                "remove registered, process-owned, or compatibility-alias keys from custom attributes",
            )
        total_bytes += name_bytes + value_bytes
        if total_bytes > MAX_RESOURCE_TOTAL_BYTES:
            _semantic_error(
                source_name,
                "observability.resource.attributes",
                "keep aggregate resource attribute keys and values within 16384 UTF-8 bytes",
            )


def _validate_resource_attribute_encoding_and_collisions(document: dict[str, Any], source_name: str) -> None:
    """Reject invalid Unicode and NFC-colliding names before JSON Schema."""

    observability = document.get("observability")
    if not isinstance(observability, dict):
        return
    resource = observability.get("resource")
    if not isinstance(resource, dict):
        return
    attributes = resource.get("attributes")
    if not isinstance(attributes, dict):
        return
    normalized_names: dict[str, str] = {}
    for name, value in attributes.items():
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        try:
            name.encode("utf-8")
            value.encode("utf-8")
        except UnicodeEncodeError:
            _semantic_error(
                source_name,
                "observability.resource.attributes",
                "use valid UTF-8 attribute names and values",
            )
        normalized = unicodedata.normalize("NFC", name)
        first = normalized_names.get(normalized)
        if first is not None and first != name:
            _semantic_error(
                source_name,
                "observability.resource.attributes",
                "remove attribute names that collide after NFC normalization",
            )
        normalized_names[normalized] = name


def _validate_destination(destination: dict[str, Any], path: str, source_name: str) -> None:
    kind = destination["kind"]
    capabilities = ("traces",) if destination.get("preset") == "galileo" else DESTINATION_CAPABILITIES[kind]
    if "send" in destination:
        selected = tuple(destination["send"]["signals"])
    elif "routes" in destination:
        selected = tuple(
            signal for signal in SIGNALS if any(signal in route["signals"] for route in destination["routes"])
        )
    else:
        selected = capabilities

    if any(signal not in capabilities for signal in selected):
        _semantic_error(source_name, f"{path}.signals", "select only signals supported by the destination kind")

    logger_name = destination.get("logger_name", "")
    if logger_name:
        if len(logger_name.encode("utf-8")) > 256:
            _semantic_error(
                source_name,
                f"{path}.logger_name",
                "use an instrumentation-scope name of 256 bytes or fewer",
            )
        if "logs" not in selected:
            _semantic_error(source_name, f"{path}.logger_name", "select logs or remove logger_name")

    for producer, sourcetype in destination.get("sourcetype_overrides", {}).items():
        if len(sourcetype.encode("utf-8")) > 256:
            _semantic_error(
                source_name,
                f"{path}.sourcetype_overrides.{producer}",
                "use a Splunk sourcetype of 256 bytes or fewer",
            )
    overrides = destination.get("signal_overrides", {})
    if any(signal not in selected for signal in overrides):
        _semantic_error(source_name, f"{path}.signal_overrides", "remove overrides for unselected signals")

    batch = destination.get("batch", {})
    queue_size = batch.get("max_queue_size", QUEUE_DEFAULTS["max_queue_size"])
    export_size = batch.get("max_export_batch_size", PUSH_BATCH_DEFAULTS["max_export_batch_size"])
    if kind in ("splunk_hec", "http_jsonl", "otlp") and export_size > queue_size:
        _semantic_error(
            source_name,
            f"{path}.batch.max_export_batch_size",
            "set max_export_batch_size no greater than max_queue_size",
        )

    if kind == "prometheus":
        _validate_prometheus(destination["listen"], destination["path"], path, source_name)
        return
    if kind not in ("splunk_hec", "http_jsonl", "otlp"):
        return

    safety = {
        "allow_private_networks": destination.get("network_safety", {}).get("allow_private_networks", False),
        "allow_cgnat": destination.get("network_safety", {}).get("allow_cgnat", False),
    }
    protocol = destination.get("protocol") or (
        "http/protobuf" if destination.get("preset") == "galileo" else "grpc" if kind == "otlp" else ""
    )
    if kind == "otlp" and protocol not in _OTLP_PROTOCOLS:
        _semantic_error(source_name, f"{path}.protocol", "use grpc, grpc/protobuf, http, or http/protobuf")
    if destination.get("preset") == "galileo" and protocol != "http/protobuf":
        _semantic_error(source_name, f"{path}.protocol", "use http/protobuf with the Galileo preset")

    endpoint = destination.get("endpoint", "")
    if endpoint:
        _validate_endpoint(
            endpoint,
            protocol,
            safety,
            f"{path}.endpoint",
            source_name,
            otlp=kind == "otlp",
        )
    if kind != "otlp":
        return
    tls = destination.get("tls", {})
    tls_insecure = tls.get("insecure", False)
    ca_cert = tls.get("ca_cert", "")
    if ca_cert and not Path(ca_cert).is_absolute():
        _semantic_error(
            source_name,
            f"{path}.tls.ca_cert",
            "use an absolute CA certificate path",
        )
    if tls_insecure and ca_cert:
        _semantic_error(
            source_name,
            f"{path}.tls.ca_cert",
            "remove ca_cert when tls.insecure is true",
        )
    for signal in selected:
        override = overrides.get(signal, {})
        override_path = override.get("path", "")
        if override_path:
            _validate_otlp_signal_path(
                override_path,
                f"{path}.signal_overrides.{signal}.path",
                source_name,
            )
        if override_path and protocol in ("grpc", "grpc/protobuf"):
            _semantic_error(
                source_name,
                f"{path}.signal_overrides.{signal}.path",
                "remove path for gRPC or use http/protobuf",
            )
        override_endpoint = override.get("endpoint") or ""
        resolved = override_endpoint or endpoint
        signal_path = f"{path}.signal_overrides.{signal}.endpoint"
        if not override_endpoint and endpoint:
            signal_path = f"{path}.endpoint"
        if not resolved:
            _semantic_error(
                source_name,
                signal_path,
                "set a destination endpoint or a selected-signal endpoint override",
            )
        _validate_endpoint(resolved, protocol, safety, signal_path, source_name, otlp=True)
        _validate_otlp_endpoint_tls(resolved, tls_insecure, signal_path, source_name)


def _validate_otlp_signal_path(value: str, path: str, source_name: str) -> None:
    if (
        not value.startswith("/")
        or any(unicodedata.category(character) == "Cc" for character in value)
        or any(character in value for character in "?#")
        or re.search(r"%(?![0-9A-Fa-f]{2})", value)
    ):
        _semantic_error(
            source_name,
            path,
            "use an absolute URL path with valid percent-encoding and no query or fragment delimiters",
        )


def _validate_prometheus(listen: str, metrics_path: str, path: str, source_name: str) -> None:
    try:
        parsed = urlsplit(f"//{listen}")
        port = parsed.port
    except ValueError:
        port = None
        parsed = None
    if (
        parsed is None
        or any(character.isspace() for character in listen)
        or any(character in listen for character in "@/?#")
        or not parsed.hostname
        or port is None
        or not 1 <= port <= 65_535
    ):
        _semantic_error(source_name, f"{path}.listen", "use a host:port listener with a valid port")
    if not metrics_path.startswith("/"):
        _semantic_error(source_name, f"{path}.path", "use an absolute metrics path beginning with /")


def _validate_endpoint(
    raw: str,
    protocol: str,
    safety: dict[str, bool],
    path: str,
    source_name: str,
    *,
    otlp: bool = False,
) -> None:
    value = raw.strip()
    if not value or len(value) > 2_048 or any(character.isspace() for character in value):
        _semantic_error(source_name, path, "use a nonempty bounded collector endpoint without whitespace")
    if "://" in value:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError:
            _semantic_error(source_name, path, "use a valid HTTP(S) endpoint without inline credentials")
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None:
            _semantic_error(source_name, path, "use a valid HTTP(S) endpoint without inline credentials")
        if otlp and ("?" in value or "#" in value):
            _semantic_error(source_name, path, "remove query and fragment data from OTLP endpoints")
        if otlp and protocol in ("grpc", "grpc/protobuf") and parsed.path not in ("", "/"):
            _semantic_error(source_name, path, "remove the path from a gRPC OTLP endpoint")
        if port is not None and not 1 <= port <= 65_535:
            _semantic_error(source_name, path, "use an endpoint port from 1 through 65535")
        host = parsed.hostname
    else:
        if protocol.startswith("http") or not protocol:
            _semantic_error(source_name, path, "use http:// or https:// for an HTTP transport")
        if any(character in value for character in "@/?#"):
            _semantic_error(source_name, path, "use a gRPC host:port authority without credentials or path data")
        try:
            parsed = urlsplit(f"//{value}")
            port = parsed.port
        except ValueError:
            _semantic_error(source_name, path, "use a valid gRPC host:port authority")
        if not parsed.hostname or port is None or not 1 <= port <= 65_535:
            _semantic_error(source_name, path, "use a valid gRPC host:port authority")
        host = parsed.hostname
    _validate_endpoint_host(host, safety, path, source_name)


def _validate_otlp_endpoint_tls(raw: str, insecure: bool, path: str, source_name: str) -> None:
    if "://" not in raw:
        return
    scheme = urlsplit(raw).scheme.lower()
    if scheme in {"http", "https"} and (scheme == "http") is not insecure:
        _semantic_error(
            source_name,
            path,
            "set tls.insecure true for http:// endpoints and false for https:// endpoints",
        )


def _validate_endpoint_host(host: str, safety: dict[str, bool], path: str, source_name: str) -> None:
    classification = classify_endpoint_host(host)
    if classification == ENDPOINT_HOST_LOCALHOST:
        if not safety["allow_private_networks"]:
            _semantic_error(source_name, path, "set allow_private_networks for an intentional localhost collector")
        return
    if classification == ENDPOINT_HOST_METADATA:
        _semantic_error(source_name, path, "use a non-metadata collector endpoint")
    if classification == ENDPOINT_HOST_INVALID:
        _semantic_error(source_name, path, "use a syntactically valid collector hostname")
    if classification == ENDPOINT_HOST_PROHIBITED:
        _semantic_error(source_name, path, "reserved, link-local, unspecified, and multicast endpoints are prohibited")
    if classification == ENDPOINT_HOST_CGNAT:
        if not safety["allow_cgnat"]:
            _semantic_error(source_name, path, "set allow_cgnat for an intentional RFC 6598 collector")
        return
    if classification == ENDPOINT_HOST_PRIVATE and not safety["allow_private_networks"]:
        _semantic_error(source_name, path, "set allow_private_networks for an intentional private collector")


def classify_endpoint_host(host: str) -> str:
    """Classify one already-parsed collector host without resolving DNS.

    The migration converter and source validator share this value-only helper so
    private-network opt-ins cannot drift.  The return value never contains the
    supplied host and is therefore safe to use in migration diagnostics.
    """

    normalized = host.strip().lower().rstrip(".")
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return ENDPOINT_HOST_LOCALHOST
    if normalized in _METADATA_HOSTS:
        return ENDPOINT_HOST_METADATA
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        if (
            len(normalized) > 253
            or ".." in normalized
            or not _HOSTNAME.fullmatch(normalized)
            or any(len(label) > 63 or label.startswith("-") or label.endswith("-") for label in normalized.split("."))
        ):
            return ENDPOINT_HOST_INVALID
        return ENDPOINT_HOST_PUBLIC
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if str(address) in _METADATA_ADDRESSES:
        return ENDPOINT_HOST_METADATA
    if address.is_link_local or address.is_unspecified or address.is_multicast:
        return ENDPOINT_HOST_PROHIBITED
    if any(address in network for network in _RESERVED_NETWORKS if address.version == network.version):
        return ENDPOINT_HOST_PROHIBITED
    if address.version == 4 and address in _CGNAT:
        return ENDPOINT_HOST_CGNAT
    if address.is_loopback or address.is_private:
        return ENDPOINT_HOST_PRIVATE
    return ENDPOINT_HOST_PUBLIC


def _built_in_field_modes() -> dict[str, dict[str, str]]:
    sensitive = {
        "metadata": "preserve",
        "identifier": "preserve",
        "content": "detect",
        "reason": "detect",
        "evidence": "detect",
        "error": "detect",
        "path": "hash",
        "credential": "remove",
    }
    return {
        "sensitive": sensitive,
        "content": dict(sensitive, content="whole", evidence="whole"),
        "strict": {
            "metadata": "preserve",
            "identifier": "preserve",
            "content": "remove",
            "reason": "remove",
            "evidence": "remove",
            "error": "remove",
            "path": "remove",
            "credential": "remove",
        },
        "legacy-v7": {
            "metadata": "preserve",
            "identifier": "whole",
            "content": "whole",
            "reason": "whole",
            "evidence": "whole",
            "error": "whole",
            "path": "whole",
            "credential": "whole",
        },
    }


def _masked_copy(value: Any, parent_key: str = "", in_headers: bool = False) -> Any:
    if isinstance(value, dict):
        if in_headers and set(value) == {"env"} and isinstance(value["env"], str):
            return {"env": value["env"]}
        result: dict[Any, Any] = {}
        for key, child in value.items():
            key_text = str(key).lower()
            headers = in_headers or key_text in _HEADER_MAP_FIELD_NAMES
            if headers and key_text not in _HEADER_MAP_FIELD_NAMES and isinstance(child, str):
                result[key] = "[REDACTED]"
            elif parent_key == "webhooks" and key_text == "url" and isinstance(child, str):
                result[key] = "[REDACTED]"
            elif key_text in {"endpoint", "base_url", "url"} and isinstance(child, str):
                result[key] = _masked_url(child)
            elif key_text in _SECRET_FIELD_NAMES and not key_text.endswith("_env"):
                result[key] = "[REDACTED]" if child else child
            else:
                result[key] = _masked_copy(child, key_text, headers)
        return result
    if isinstance(value, list):
        return [_masked_copy(child, parent_key, in_headers) for child in value]
    return copy.deepcopy(value)


def _resource_value_has_inline_credentials(value: str) -> bool:
    try:
        return urlsplit(value).username is not None
    except ValueError:
        # Custom resource values are arbitrary text, so a malformed URL-like
        # value is not itself an error. Still fail closed when its authority
        # explicitly contains userinfo, even if a malformed host prevented
        # urllib from returning a parsed result.
        prefix, separator, remainder = value.partition("://")
        if not separator or not prefix:
            return False
        authority = re.split(r"[/?#]", remainder, maxsplit=1)[0]
        return "@" in authority


def _masked_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "[REDACTED_URL]"
    if parsed.username is not None or parsed.password is not None:
        return "[REDACTED_URL]"
    path = parsed.path
    if path not in {"", "/"}:
        path = "/[REDACTED]" if path.startswith("/") else "[REDACTED]"
    query = "[REDACTED]" if parsed.query else ""
    fragment = "[REDACTED]" if parsed.fragment else ""
    return urlunsplit((parsed.scheme, parsed.netloc, path, query, fragment))


__all__ = [
    "BUCKETS",
    "BUILT_IN_PROFILES",
    "DESTINATION_CAPABILITIES",
    "DESTINATION_BATCH_MODES",
    "DETECTOR_GROUPS",
    "FIELD_CLASSES",
    "FIELD_MODES",
    "PUSH_BATCH_BOUNDS",
    "PUSH_BATCH_DEFAULTS",
    "QUEUE_BOUNDS",
    "QUEUE_DEFAULTS",
    "ROUTE_ACTIONS",
    "SELECTOR_FIELDS",
    "SEVERITIES",
    "SIGNALS",
    "V8ConfigError",
    "ValidatedV8Config",
    "load_validate_v8",
    "observability_v8_parity_contract",
    "validate_v8_source",
]
