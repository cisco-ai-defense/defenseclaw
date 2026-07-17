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

"""Pure, deterministic v7-to-v8 observability configuration conversion.

This module deliberately owns no files, process environment, locks, backups, or
service lifecycle.  The upgrade migration supplies the exact source bytes and an
explicit environment snapshot, then activates the returned candidate and
ancillary environment edits as one rollback unit.  Secret values are carried
only in ``EnvironmentEdit.value`` (excluded from representations); they never
enter candidate YAML, summaries, warnings, or exceptions.

The converter rewrites only legacy observability-owned root entries.  Unrelated
source spans remain byte-for-byte identical, including comments, the operator
ASCII guide, key order, newline style, and scalar quoting.  Comments inside a
section whose schema changes are not blindly reattached to a different field;
the result reports that bounded reformatting as a warning.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import math
import os
import re
from collections import deque
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Final
from urllib.parse import unquote, urlsplit, urlunsplit

import yaml
from yaml.events import (
    AliasEvent,
    MappingEndEvent,
    MappingStartEvent,
    ScalarEvent,
    SequenceEndEvent,
    SequenceStartEvent,
)
from yaml.nodes import MappingNode, Node, ScalarNode

from defenseclaw.observability.v8_compatibility import (
    V7CompatibilityError,
    V7CompatibilitySelection,
    V7Selector,
    load_packaged_v7_compatibility_selection,
    load_v7_compatibility_selection,
)
from defenseclaw.observability.v8_config import (
    BUCKETS,
    CONFIGURABLE_CORE_RESOURCE_ATTRIBUTE_KEYS,
    ENDPOINT_HOST_CGNAT,
    ENDPOINT_HOST_LOCALHOST,
    ENDPOINT_HOST_PRIVATE,
    MAX_MAPPING_ENTRIES,
    MAX_ROUTES_PER_DESTINATION,
    MAX_SOURCE_BYTES,
    MAX_YAML_DEPTH,
    MAX_YAML_NODES,
    RESERVED_RESOURCE_ATTRIBUTE_KEYS,
    V8ConfigError,
    _shape,
    _StrictLoader,
    classify_endpoint_host,
    load_validate_v8,
)

_REDACTION_TRUE: Final = frozenset({"1", "true", "yes", "on"})
_JSONL_DISABLE_TRUE: Final = frozenset({"1", "true", "yes", "on", "enable", "enabled"})
_OTEL_TRUE: Final = frozenset({"1", "t", "T", "TRUE", "true", "True"})
_OTEL_FALSE: Final = frozenset({"0", "f", "F", "FALSE", "false", "False"})
_TLS_TRUE: Final = frozenset({"1", "true", "yes", "on"})
_TLS_FALSE: Final = frozenset({"0", "false", "no", "off"})
_OFF_LIKE: Final = frozenset({"0", "false", "no", "off"})
_SIGNALS: Final = ("logs", "traces", "metrics")
_NAME_RE: Final = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_ENV_RE: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_EXACT_ENV_REF: Final = re.compile(r"^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$")
_SHELL_SPECIAL: Final = frozenset("*#$@!?-0123456789")
_MAX_ENVIRONMENT_ENTRIES: Final = 4_096
_MAX_ENVIRONMENT_VALUE_BYTES: Final = 256 * 1024
_MAX_ENVIRONMENT_TOTAL_BYTES: Final = MAX_SOURCE_BYTES
_MAX_SENSITIVE_LITERALS: Final = 4_096
_MAX_SENSITIVE_LITERAL_BYTES: Final = 256 * 1024
_V7_OTEL_KEYS: Final = frozenset(
    {
        "enabled",
        "endpoint",
        "protocol",
        "headers",
        "tls",
        "batch",
        "resource",
        "traces",
        "logs",
        "metrics",
        "destinations",
    }
)
_V7_DESTINATION_KEYS: Final = frozenset(
    {
        "name",
        "preset",
        "enabled",
        "endpoint",
        "protocol",
        "headers",
        "tls",
        "batch",
        "traces",
        "logs",
        "metrics",
        "span_filter",
    }
)
_V7_SIGNAL_KEYS: Final = {
    "traces": frozenset({"enabled", "sampler", "sampler_arg", "endpoint", "protocol", "url_path"}),
    "logs": frozenset({"enabled", "emit_individual_findings", "endpoint", "protocol", "url_path"}),
    "metrics": frozenset({"enabled", "export_interval_s", "temporality", "endpoint", "protocol", "url_path"}),
}
_V7_SINK_KEYS: Final = frozenset(
    {
        "name",
        "kind",
        "enabled",
        "batch_size",
        "flush_interval_s",
        "timeout_s",
        "min_severity",
        "actions",
        "splunk_hec",
        "otlp_logs",
        "http_jsonl",
    }
)
_V7_BATCH_KEYS: Final = frozenset({"max_queue_size", "max_export_batch_size", "scheduled_delay_ms"})
_V7_TLS_KEYS: Final = frozenset({"insecure", "ca_cert"})
_V7_SPAN_FILTER_KEYS: Final = frozenset({"require_operation", "require_attributes", "operations"})
_V7_SPAN_FILTER_OPERATION_KEYS: Final = frozenset({"name", "require_attributes"})
_V7_OTEL_BATCH_DEFAULTS: Final = {
    "max_queue_size": 2048,
    "max_export_batch_size": 512,
    "scheduled_delay_ms": 5000,
}
# Exact historical Galileo v7 preset filter accepted by the upgrade boundary.
# Keep this source-shape constant local: an upgrade runs inside the already
# imported baseline CLI after replacing its wheel, so importing the target
# ``observability.presets`` module can resolve to an older cached module that
# predates GALILEO. Target runtime policy still comes from the generated
# compatibility selection; this tuple only recognizes the legacy input shape.
_V7_GALILEO_SPAN_FILTER_OPERATIONS: Final = (
    (
        "chat",
        (
            "gen_ai.operation.name",
            "gen_ai.provider.name",
            "gen_ai.request.model",
            "gen_ai.input.messages",
            "gen_ai.output.messages",
        ),
    ),
    (
        "invoke_agent",
        (
            "gen_ai.operation.name",
            "gen_ai.agent.name",
            "gen_ai.provider.name",
            "openinference.span.kind",
            "gen_ai.input.messages",
            "gen_ai.output.messages",
        ),
    ),
    (
        "execute_tool",
        (
            "gen_ai.operation.name",
            "gen_ai.tool.name",
            "openinference.span.kind",
            "gen_ai.tool.call.arguments",
            "gen_ai.tool.call.result",
            "gen_ai.input.messages",
            "gen_ai.output.messages",
        ),
    ),
)


class V8MigrationError(ValueError):
    """Actionable, value-safe source migration error."""

    def __init__(self, code: str, path: str, action: str, *, source_name: str = "config.yaml") -> None:
        self.code = code
        self.path = path
        self.action = action
        self.source_name = source_name
        super().__init__(f"{source_name}: cannot migrate {path} ({code}); {action}")


class V8MigrationDependencyError(V8MigrationError):
    """A migration requires a generated target artifact that is not supplied."""


@dataclass(frozen=True)
class EnvironmentReference:
    """Exact candidate destination field that consumes a protected value."""

    destination: str
    path: tuple[str, ...]


@dataclass(frozen=True)
class EnvironmentDependency:
    """One environment input whose exact presence/value influenced conversion."""

    name: str
    present: bool
    value_sha256: str = field(repr=False)


@dataclass(frozen=True)
class EnvironmentEdit:
    """One secret-bearing ancillary edit for the caller-owned environment file.

    P7 applies these under the config lock, includes the environment file in the
    backup set, and restores config plus environment together on failure.
    """

    name: str
    value: str = field(repr=False)
    value_sha256: str = field(repr=False)
    references: tuple[EnvironmentReference, ...] = ()
    operation: str = "set_if_absent"
    backup_required: bool = True
    rollback_with_config: bool = True


@dataclass(frozen=True)
class V8MigrationSummary:
    """Bounded prompt/preview data containing no source values or secret names."""

    source_version: int
    destination_version: int
    otlp_destinations: int
    audit_destinations: int
    local_destinations: int
    environment_edits: int
    redaction_intent: str
    judge_body_retention: str
    local_observability: str
    resource_migrations: tuple[str, ...] = ()

    def lines(self) -> tuple[str, ...]:
        return (
            f"{self.otlp_destinations} OTel destinations",
            f"{self.audit_destinations} audit sinks",
            f"{self.local_destinations} local JSONL/console destinations",
            f"redaction intent: {self.redaction_intent}",
            f"judge-body retention: {self.judge_body_retention}",
            f"local observability: {self.local_observability}",
            "resource migrations: " + (",".join(self.resource_migrations) or "none"),
            f"{self.environment_edits} protected environment edits",
        )


@dataclass(frozen=True)
class V8MigrationResult:
    """Immutable in-memory migration output."""

    candidate: bytes = field(repr=False)
    source_sha256: str = field(repr=False)
    candidate_sha256: str = field(repr=False)
    changed: bool
    already_v8: bool
    effective_data_dir: str | None
    warnings: tuple[str, ...]
    environment_edits: tuple[EnvironmentEdit, ...] = field(repr=False)
    summary: V8MigrationSummary
    environment_dependencies: tuple[EnvironmentDependency, ...] = field(default=(), repr=False)


class _TrackedEnvironment(Mapping[str, str]):
    """Mapping that records only keys whose values affect the candidate."""

    def __init__(self, source: Mapping[str, str]) -> None:
        self._source = dict(source)
        self._consulted: set[str] = set()

    def __getitem__(self, key: str) -> str:
        self._consulted.add(key)
        return self._source[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._source)

    def __len__(self) -> int:
        return len(self._source)

    def dependencies(self) -> tuple[EnvironmentDependency, ...]:
        return tuple(
            EnvironmentDependency(
                name=name,
                present=name in self._source,
                value_sha256=_sha256(self._source.get(name, "").encode("utf-8")),
            )
            for name in sorted(self._consulted)
        )


@dataclass
class _Context:
    source_name: str
    environment: Mapping[str, str]
    compatibility_selection: V7CompatibilitySelection
    warnings: list[str] = field(default_factory=list)
    edits: dict[str, EnvironmentEdit] = field(default_factory=dict)
    sensitive_values: set[str] = field(default_factory=set, repr=False)
    sensitive_value_bytes: int = field(default=0, repr=False)
    used_names: set[str] = field(default_factory=set)
    resource_migrations: list[str] = field(default_factory=list)
    effective_data_dir: str = ""
    _comment_scrubber: _LiteralScrubber | None = field(default=None, repr=False)

    def warning(self, code: str) -> None:
        if code not in self.warnings:
            self.warnings.append(code)

    def resource_migration(self, code: str) -> None:
        """Record one content-free resource conversion in preview and warnings."""

        if code not in self.resource_migrations:
            self.resource_migrations.append(code)
        self.warning(f"resource_migration:{code}")

    def scrub_comment(self, value: str) -> str:
        if not self.sensitive_values:
            return value
        if self._comment_scrubber is None:
            self._comment_scrubber = _LiteralScrubber(self.sensitive_values)
        return self._comment_scrubber.scrub(value)

    def add_sensitive_value(self, value: str) -> None:
        """Retain one bounded literal for value-safe comment scrubbing."""

        if not value or value in self.sensitive_values:
            return
        try:
            value_bytes = len(value.encode("utf-8"))
        except UnicodeEncodeError:
            raise V8MigrationError(
                "invalid_sensitive_value",
                "$.observability",
                "use UTF-8-compatible telemetry credentials and header values",
                source_name=self.source_name,
            ) from None
        if (
            len(self.sensitive_values) >= _MAX_SENSITIVE_LITERALS
            or self.sensitive_value_bytes + value_bytes > _MAX_SENSITIVE_LITERAL_BYTES
        ):
            raise V8MigrationError(
                "sensitive_data_too_large",
                "$.observability",
                "reduce migrated header and credential value count or aggregate size",
                source_name=self.source_name,
            )
        self.sensitive_values.add(value)
        self.sensitive_value_bytes += value_bytes


class _LiteralScrubber:
    """Linear-time multi-literal replacement for secret-bearing comments."""

    def __init__(self, values: Sequence[str] | set[str]) -> None:
        self.transitions: list[dict[str, int]] = [{}]
        self.failures = [0]
        self.longest_output = [0]
        for value in sorted({item for item in values if item}):
            state = 0
            for character in value:
                next_state = self.transitions[state].get(character)
                if next_state is None:
                    next_state = len(self.transitions)
                    self.transitions[state][character] = next_state
                    self.transitions.append({})
                    self.failures.append(0)
                    self.longest_output.append(0)
                state = next_state
            self.longest_output[state] = max(self.longest_output[state], len(value))

        pending: deque[int] = deque()
        for state in self.transitions[0].values():
            pending.append(state)
        while pending:
            state = pending.popleft()
            for character, next_state in self.transitions[state].items():
                pending.append(next_state)
                failure = self.failures[state]
                while failure and character not in self.transitions[failure]:
                    failure = self.failures[failure]
                self.failures[next_state] = self.transitions[failure].get(character, 0)
                self.longest_output[next_state] = max(
                    self.longest_output[next_state],
                    self.longest_output[self.failures[next_state]],
                )

    def scrub(self, value: str) -> str:
        state = 0
        matches: list[tuple[int, int]] = []
        for index, character in enumerate(value):
            while state and character not in self.transitions[state]:
                state = self.failures[state]
            state = self.transitions[state].get(character, 0)
            if length := self.longest_output[state]:
                matches.append((index - length + 1, index + 1))
        if not matches:
            return value
        merged: list[tuple[int, int]] = []
        for start, end in matches:
            if merged and start < merged[-1][1]:
                merged[-1] = (min(merged[-1][0], start), max(merged[-1][1], end))
            else:
                merged.append((start, end))
        for start, end in reversed(merged):
            value = value[:start] + "[REDACTED]" + value[end:]
        return value


def convert_v7_observability_to_v8(
    source: bytes | str,
    environment: Mapping[str, str],
    *,
    source_name: str = "config.yaml",
    compatibility_selection: V7CompatibilitySelection | Mapping[str, Any] | None = None,
    effective_data_dir: str | None = None,
) -> V8MigrationResult:
    """Build a complete v8 candidate without reading or changing external state.

    ``environment`` is an explicit snapshot.  The function never consults
    ``os.environ``. Every v7 conversion requires the generated, typed
    compatibility selection; a valid v8 no-op does not.
    """

    raw = _source_bytes(source, source_name)
    _preflight_yaml_shape(raw, source_name)
    source_digest = _sha256(raw)
    environment_copy = _validate_environment(environment, source_name)

    try:
        valid_v8 = load_validate_v8(raw, source_name=source_name)
    except (V8ConfigError, RecursionError, OverflowError):
        valid_v8 = None
    if valid_v8 is not None:
        configured_data_dir = valid_v8.source.get("data_dir")
        resolved_data_dir = (
            configured_data_dir
            if isinstance(configured_data_dir, str) and Path(configured_data_dir).is_absolute()
            else effective_data_dir
        )
        # A pure already-v8 preview remains an exact no-op even when the caller
        # has not resolved runtime defaults. Activation rejects the empty
        # binding; the upgrade path always supplies the compiler-resolved root.
        if not isinstance(resolved_data_dir, str) or not Path(resolved_data_dir).is_absolute():
            resolved_data_dir = None
        else:
            resolved_data_dir = os.path.abspath(resolved_data_dir)
        summary = V8MigrationSummary(8, 8, 0, 0, 0, 0, "unchanged", "unchanged", "unchanged")
        return V8MigrationResult(
            candidate=raw,
            source_sha256=source_digest,
            candidate_sha256=source_digest,
            changed=False,
            already_v8=True,
            effective_data_dir=resolved_data_dir,
            warnings=(),
            environment_edits=(),
            summary=summary,
        )

    document = _parse_v7(raw, source_name)
    selection = _resolve_compatibility_selection(compatibility_selection, source_name)
    source_version = int(document.get("config_version") or 7)
    tracked_environment = _TrackedEnvironment(environment_copy)
    ctx = _Context(source_name, tracked_environment, selection)
    _validate_supported_v7(document, ctx)

    redaction_disabled = _environment_true(
        tracked_environment.get("DEFENSECLAW_DISABLE_REDACTION", ""), _REDACTION_TRUE
    ) or (
        _mapping(document.get("privacy"), "$.privacy", ctx).get("disable_redaction") is True
        if "privacy" in document
        else False
    )
    if _environment_true(tracked_environment.get("DEFENSECLAW_DISABLE_REDACTION", ""), _REDACTION_TRUE):
        ctx.warning("environment_decision:DEFENSECLAW_DISABLE_REDACTION")
    profile = "none" if redaction_disabled else "legacy-v7"
    # Redacting v7 sources target the shipped immutable compatibility profile,
    # never a synthesized approximation declared as a mutable custom profile.

    observability, otlp_count, audit_count, local_state = _build_observability(
        document, profile, effective_data_dir, ctx
    )
    retention, guardrail_value = _judge_retention(document, tracked_environment, ctx)
    candidate = _rewrite_source(raw, document, observability, guardrail_value, ctx)

    # Python validation is a fast parity gate. P7 must additionally compile the
    # complete candidate through the canonical Go compiler before activation.
    try:
        load_validate_v8(candidate, source_name=source_name)
    except V8ConfigError:
        raise V8MigrationError(
            "candidate_validation_failed",
            "$.observability",
            "fix the reported supported-v7 source shape before retrying the upgrade",
            source_name=source_name,
        ) from None

    edits = tuple(ctx.edits[name] for name in sorted(ctx.edits))
    summary = V8MigrationSummary(
        source_version=source_version,
        destination_version=8,
        otlp_destinations=otlp_count,
        audit_destinations=audit_count,
        local_destinations=2,
        environment_edits=len(edits),
        redaction_intent="unredacted" if redaction_disabled else "legacy-v7-compatible",
        judge_body_retention=retention,
        local_observability=local_state,
        resource_migrations=tuple(sorted(ctx.resource_migrations)),
    )
    return V8MigrationResult(
        candidate=candidate,
        source_sha256=source_digest,
        candidate_sha256=_sha256(candidate),
        changed=candidate != raw or bool(edits),
        already_v8=False,
        effective_data_dir=ctx.effective_data_dir,
        warnings=tuple(sorted(ctx.warnings)),
        environment_edits=edits,
        summary=summary,
        environment_dependencies=tracked_environment.dependencies(),
    )


def _source_bytes(source: bytes | str, source_name: str) -> bytes:
    if isinstance(source, bytes):
        raw = source
    elif isinstance(source, str):
        try:
            raw = source.encode("utf-8")
        except UnicodeEncodeError:
            raise V8MigrationError("invalid_utf8", "$", "save the source as UTF-8", source_name=source_name) from None
    else:
        raise V8MigrationError("invalid_source_type", "$", "supply UTF-8 bytes or text", source_name=source_name)
    if len(raw) > MAX_SOURCE_BYTES:
        raise V8MigrationError("source_too_large", "$", "reduce the source below 4 MiB", source_name=source_name)
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        raise V8MigrationError("invalid_utf8", "$", "save the source as UTF-8", source_name=source_name) from None
    return raw


def _resolve_compatibility_selection(
    value: V7CompatibilitySelection | Mapping[str, Any] | None,
    source_name: str,
) -> V7CompatibilitySelection:
    if isinstance(value, V7CompatibilitySelection):
        return value
    if value is None:
        try:
            return load_packaged_v7_compatibility_selection()
        except (OSError, V7CompatibilityError):
            raise V8MigrationDependencyError(
                "compatibility_selection_unavailable",
                "$.observability",
                "reinstall DefenseClaw with the checked generated v7 exporter compatibility selection",
                source_name=source_name,
            ) from None
    try:
        return load_v7_compatibility_selection(value)
    except V7CompatibilityError as exc:
        raise V8MigrationDependencyError(
            "compatibility_selection_invalid",
            exc.path,
            "regenerate the complete v7 exporter compatibility selection",
            source_name=source_name,
        ) from None


def _validate_environment(environment: Mapping[str, str], source_name: str) -> dict[str, str]:
    if not isinstance(environment, Mapping):
        raise V8MigrationError(
            "invalid_environment", "$environment", "supply an explicit string mapping", source_name=source_name
        )
    result: dict[str, str] = {}
    total_bytes = 0
    for name, value in environment.items():
        if len(result) >= _MAX_ENVIRONMENT_ENTRIES:
            raise V8MigrationError(
                "environment_too_large",
                "$environment",
                "supply at most 4096 explicit environment entries",
                source_name=source_name,
            )
        if not isinstance(name, str) or not _ENV_RE.fullmatch(name) or not isinstance(value, str):
            raise V8MigrationError(
                "invalid_environment",
                "$environment",
                "use valid environment names and string values",
                source_name=source_name,
            )
        try:
            value_bytes = len(value.encode("utf-8"))
        except UnicodeEncodeError:
            raise V8MigrationError(
                "invalid_environment",
                "$environment",
                "use UTF-8-compatible string values",
                source_name=source_name,
            ) from None
        if value_bytes > _MAX_ENVIRONMENT_VALUE_BYTES:
            raise V8MigrationError(
                "environment_value_too_large",
                "$environment",
                "reduce each explicit environment value below 256 KiB",
                source_name=source_name,
            )
        total_bytes += len(name) + value_bytes
        if total_bytes > _MAX_ENVIRONMENT_TOTAL_BYTES:
            raise V8MigrationError(
                "environment_too_large",
                "$environment",
                "reduce the explicit environment snapshot below 4 MiB",
                source_name=source_name,
            )
        result[name] = value
    return result


def _preflight_yaml_shape(raw: bytes, source_name: str) -> None:
    """Reject oversized YAML structure before constructing Python containers."""

    nodes = 0
    # Frames are ``[is_mapping, expecting_key, mapping_entries]``. Marking a
    # parent child at its start handles scalar and nested collection keys or
    # values without retaining the parsed document.
    frames: list[list[int | bool]] = []

    def record_parent_child() -> None:
        if not frames or frames[-1][0] is not True:
            return
        frame = frames[-1]
        if frame[1] is True:
            frame[2] = int(frame[2]) + 1
            if int(frame[2]) > MAX_MAPPING_ENTRIES:
                raise V8MigrationError(
                    "source_too_complex",
                    "$",
                    "reduce YAML mapping size before upgrading",
                    source_name=source_name,
                )
        frame[1] = frame[1] is not True

    try:
        events = yaml.parse(raw.decode("utf-8"), Loader=_StrictLoader)
        for event in events:
            if isinstance(event, AliasEvent):
                raise V8MigrationError(
                    "invalid_yaml",
                    "$",
                    "remove duplicate keys, aliases, merge keys, or malformed YAML",
                    source_name=source_name,
                )
            if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
                record_parent_child()
                nodes += 1
                frames.append([isinstance(event, MappingStartEvent), True, 0])
                if len(frames) > MAX_YAML_DEPTH:
                    raise V8MigrationError(
                        "source_too_complex",
                        "$",
                        "reduce YAML node count or nesting depth",
                        source_name=source_name,
                    )
            elif isinstance(event, (MappingEndEvent, SequenceEndEvent)):
                frames.pop()
            elif isinstance(event, ScalarEvent):
                record_parent_child()
                nodes += 1
            if nodes > MAX_YAML_NODES:
                raise V8MigrationError(
                    "source_too_complex",
                    "$",
                    "reduce YAML node count or nesting depth",
                    source_name=source_name,
                )
    except V8MigrationError:
        raise
    except (yaml.YAMLError, RecursionError, OverflowError):
        raise V8MigrationError(
            "invalid_yaml",
            "$",
            "remove duplicate keys, aliases, merge keys, or malformed YAML",
            source_name=source_name,
        ) from None


def _parse_v7(raw: bytes, source_name: str) -> dict[str, Any]:
    text = raw.decode("utf-8")
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
        lexical_attributes, attributes_node = _resource_attribute_lexemes(root, source_name)
        load_text = text
        if attributes_node is not None:
            start = attributes_node.start_mark.index
            end = attributes_node.end_mark.index
            replaced_span = text[start:end]
            trailing_whitespace = re.search(r"\s*$", replaced_span)
            replacement = "{}" + (trailing_whitespace.group(0) if trailing_whitespace else "")
            load_text = text[:start] + replacement + text[end:]
        document = yaml.load(load_text, Loader=_StrictLoader)
    except (RecursionError, OverflowError):
        raise V8MigrationError(
            "source_too_complex",
            "$",
            "reduce YAML nesting before upgrading",
            source_name=source_name,
        ) from None
    except yaml.YAMLError:
        raise V8MigrationError(
            "invalid_yaml",
            "$",
            "remove duplicate keys, aliases, merge keys, or malformed YAML",
            source_name=source_name,
        ) from None
    if not isinstance(document, dict):
        raise V8MigrationError("invalid_root", "$", "use one YAML mapping", source_name=source_name)
    if lexical_attributes is not None:
        otel = document.get("otel")
        if isinstance(otel, dict):
            resource = otel.get("resource")
            if isinstance(resource, dict):
                resource["attributes"] = lexical_attributes
    nodes, depth = _shape(document)
    if nodes > MAX_YAML_NODES or depth > MAX_YAML_DEPTH:
        raise V8MigrationError(
            "source_too_complex", "$", "reduce YAML node count or nesting depth", source_name=source_name
        )
    version = document.get("config_version", 0)
    if type(version) is not int or version < 0 or version > 7:
        if version == 8:
            action = "repair the invalid v8 source; an invalid v8 document is never interpreted as v7"
        else:
            action = "upgrade through a release supporting this historical configuration version"
        raise V8MigrationError("unsupported_version", "$.config_version", action, source_name=source_name)
    if version in {1, 2, 3, 4}:
        # Those sources require the existing v1-v5 guardrail/LLM semantic
        # migrations before their version stamp can safely advance. The
        # upgrade command performs that normalization in memory and invokes
        # this pure converter again; no intermediate release or source write
        # is part of this dependency contract. Versions 5 and 6 need only the
        # no-op v5-v6 step and the flat-OTel migration implemented here.
        raise V8MigrationDependencyError(
            "historical_prenormalization_required",
            "$.config_version",
            "have defenseclaw upgrade run the existing v1-v7 configuration migrations in memory, "
            "then supply the normalized v7 source without an intermediate release or write",
            source_name=source_name,
        )
    if version == 0 and _has_v8_only_observability(document):
        raise V8MigrationError(
            "ambiguous_unversioned_source",
            "$.observability",
            "set the correct config_version and remove mixed v7/v8 observability fields",
            source_name=source_name,
        )
    return document


def _resource_attribute_lexemes(root: Node | None, source_name: str) -> tuple[dict[str, str] | None, Node | None]:
    """Extract the lexical v7 OTel resource map before SafeLoader coercion."""

    if not isinstance(root, MappingNode):
        return None, None
    otel_pair = _mapping_node_pair(root, "otel")
    if otel_pair is None or not isinstance(otel_pair[1], MappingNode):
        return None, None
    resource_pair = _mapping_node_pair(otel_pair[1], "resource")
    if resource_pair is None or not isinstance(resource_pair[1], MappingNode):
        return None, None
    attributes_pair = _mapping_node_pair(resource_pair[1], "attributes")
    if attributes_pair is None:
        return None, None
    attributes_node = attributes_pair[1]
    if isinstance(attributes_node, ScalarNode) and attributes_node.tag == "tag:yaml.org,2002:null":
        return {}, attributes_node
    if not isinstance(attributes_node, MappingNode):
        raise V8MigrationError(
            "unsupported_type",
            "$.otel.resource.attributes",
            "use a mapping with scalar keys and values",
            source_name=source_name,
        )
    result: dict[str, str] = {}
    seen: set[str] = set()
    for key_node, value_node in attributes_node.value:
        if not isinstance(key_node, ScalarNode) or not isinstance(value_node, ScalarNode):
            raise V8MigrationError(
                "unsupported_type",
                "$.otel.resource.attributes",
                "use a mapping with scalar keys and values",
                source_name=source_name,
            )
        key = key_node.value
        if key in seen:
            raise V8MigrationError(
                "invalid_yaml",
                "$.otel.resource.attributes",
                "remove duplicate resource attribute keys",
                source_name=source_name,
            )
        seen.add(key)
        if value_node.tag != "tag:yaml.org,2002:null":
            result[key] = value_node.value
    return result, attributes_node


def _has_v8_only_observability(document: Mapping[str, Any]) -> bool:
    obs = document.get("observability")
    if not isinstance(obs, Mapping):
        return obs is not None
    if any(key != "connectors" for key in obs):
        return True
    connectors = obs.get("connectors", {})
    if not isinstance(connectors, Mapping):
        return True
    return any(
        not isinstance(value, Mapping) or any(key not in {"audit_sinks", "webhooks"} for key in value)
        for value in connectors.values()
    )


def _validate_supported_v7(document: Mapping[str, Any], ctx: _Context) -> None:
    for root_path in ("audit_db", "judge_bodies_db"):
        if root_path in document and (not isinstance(document[root_path], str) or not document[root_path]):
            raise _error(ctx, "unsupported_type", f"$.{root_path}", "use a nonempty path string")
    otel = _mapping(document.get("otel"), "$.otel", ctx) if "otel" in document else {}
    _reject_unknown(otel, _V7_OTEL_KEYS, "$.otel", ctx)
    _validate_otel_nested(otel, "$.otel", ctx, allow_span_filter=False)
    _optional_bool(otel, "enabled", "$.otel.enabled", ctx)
    _optional_string(otel, "endpoint", "$.otel.endpoint", ctx)
    _optional_string(otel, "protocol", "$.otel.protocol", ctx)
    for signal in _SIGNALS:
        value = _mapping(otel.get(signal), f"$.otel.{signal}", ctx) if signal in otel else {}
        _reject_unknown(value, _V7_SIGNAL_KEYS[signal], f"$.otel.{signal}", ctx)
        _optional_bool(value, "enabled", f"$.otel.{signal}.enabled", ctx)
        if signal == "logs":
            _optional_bool(value, "emit_individual_findings", "$.otel.logs.emit_individual_findings", ctx)
        for string_key in ("sampler", "sampler_arg", "endpoint", "protocol", "url_path", "temporality"):
            _optional_string(value, string_key, f"$.otel.{signal}.{string_key}", ctx)
        _optional_int(value, "export_interval_s", f"$.otel.{signal}.export_interval_s", ctx)
    destinations = _sequence(otel.get("destinations"), "$.otel.destinations", ctx) if "destinations" in otel else []
    seen_destination_names: set[str] = set()
    for index, value in enumerate(destinations):
        destination = _mapping(value, f"$.otel.destinations[{index}]", ctx)
        _reject_unknown(destination, _V7_DESTINATION_KEYS, f"$.otel.destinations[{index}]", ctx)
        _validate_otel_nested(destination, f"$.otel.destinations[{index}]", ctx, allow_span_filter=True)
        _optional_bool(destination, "enabled", f"$.otel.destinations[{index}].enabled", ctx)
        for string_key in ("name", "preset", "endpoint", "protocol"):
            _optional_string(destination, string_key, f"$.otel.destinations[{index}].{string_key}", ctx)
        destination_name = _first_nonempty_text(destination.get("name"))
        if not destination_name:
            raise _error(
                ctx,
                "unsupported_destination_name",
                f"$.otel.destinations[{index}].name",
                "use the required nonempty v7 destination name",
            )
        if destination_name in seen_destination_names:
            raise _error(
                ctx,
                "duplicate_destination_name",
                f"$.otel.destinations[{index}].name",
                "keep exactly one v7 destination with each trimmed name",
            )
        seen_destination_names.add(destination_name)
        for signal in _SIGNALS:
            signal_value = (
                _mapping(destination.get(signal), f"$.otel.destinations[{index}].{signal}", ctx)
                if signal in destination
                else {}
            )
            _reject_unknown(signal_value, _V7_SIGNAL_KEYS[signal], f"$.otel.destinations[{index}].{signal}", ctx)
            _optional_bool(signal_value, "enabled", f"$.otel.destinations[{index}].{signal}.enabled", ctx)
            if signal == "logs":
                _optional_bool(
                    signal_value,
                    "emit_individual_findings",
                    f"$.otel.destinations[{index}].logs.emit_individual_findings",
                    ctx,
                )
            for string_key in (
                "sampler",
                "sampler_arg",
                "endpoint",
                "protocol",
                "url_path",
                "temporality",
            ):
                _optional_string(
                    signal_value,
                    string_key,
                    f"$.otel.destinations[{index}].{signal}.{string_key}",
                    ctx,
                )
            _optional_int(
                signal_value,
                "export_interval_s",
                f"$.otel.destinations[{index}].{signal}.export_interval_s",
                ctx,
            )
    sinks = _sequence(document.get("audit_sinks"), "$.audit_sinks", ctx) if "audit_sinks" in document else []
    for index, value in enumerate(sinks):
        _validate_sink(_mapping(value, f"$.audit_sinks[{index}]", ctx), f"$.audit_sinks[{index}]", ctx)
    obs = _mapping(document.get("observability"), "$.observability", ctx) if "observability" in document else {}
    _reject_unknown(obs, frozenset({"connectors"}), "$.observability", ctx)
    connectors = _mapping(obs.get("connectors"), "$.observability.connectors", ctx) if "connectors" in obs else {}
    normalized_connectors: dict[str, str] = {}
    for connector, value in connectors.items():
        if not isinstance(connector, str) or not connector.strip():
            raise _error(
                ctx,
                "unsupported_connector_name",
                "$.observability.connectors",
                "use a nonempty connector name",
            )
        normalized = _normalize_legacy_connector_name(connector)
        if normalized in normalized_connectors:
            raise _error(
                ctx,
                "duplicate_connector_alias",
                "$.observability.connectors",
                "keep only one case-insensitive open-hands/open_hands alias for each connector",
            )
        if not _NAME_RE.fullmatch(normalized):
            raise _error(
                ctx,
                "unsupported_connector_name",
                f"$.observability.connectors.{connector}",
                "rename the connector to a stable lowercase v8 name before upgrading",
            )
        normalized_connectors[normalized] = connector
        config = _mapping(value, f"$.observability.connectors.{connector}", ctx)
        _reject_unknown(config, frozenset({"audit_sinks", "webhooks"}), f"$.observability.connectors.{connector}", ctx)
        if "audit_sinks" in config:
            for index, sink in enumerate(_sequence(config["audit_sinks"], "audit_sinks", ctx)):
                _validate_sink(_mapping(sink, "audit_sinks[]", ctx), "audit_sinks[]", ctx)
    if "privacy" in document:
        privacy = _mapping(document["privacy"], "$.privacy", ctx)
        _reject_unknown(
            privacy,
            frozenset({"disable_redaction"}),
            "$.privacy",
            ctx,
        )
        _optional_bool(privacy, "disable_redaction", "$.privacy.disable_redaction", ctx)


def _validate_otel_nested(source: Mapping[str, Any], path: str, ctx: _Context, *, allow_span_filter: bool) -> None:
    if "batch" in source:
        batch = _mapping(source["batch"], f"{path}.batch", ctx)
        _reject_unknown(batch, _V7_BATCH_KEYS, f"{path}.batch", ctx)
        for key in _V7_BATCH_KEYS:
            _optional_int(batch, key, f"{path}.batch.{key}", ctx)
    if "tls" in source:
        tls = _mapping(source["tls"], f"{path}.tls", ctx)
        _reject_unknown(tls, _V7_TLS_KEYS, f"{path}.tls", ctx)
        _optional_bool(tls, "insecure", f"{path}.tls.insecure", ctx)
        _optional_string(tls, "ca_cert", f"{path}.tls.ca_cert", ctx)
    if "headers" in source:
        headers = _mapping(source["headers"], f"{path}.headers", ctx)
        if any(not isinstance(name, str) or not isinstance(value, str) for name, value in headers.items()):
            raise _error(ctx, "unsupported_type", f"{path}.headers", "use string header names and values")
    if "resource" in source:
        resource = _mapping(source["resource"], f"{path}.resource", ctx)
        _reject_unknown(resource, frozenset({"attributes"}), f"{path}.resource", ctx)
        if "attributes" in resource and resource["attributes"] is not None:
            attributes = _mapping(resource["attributes"], f"{path}.resource.attributes", ctx)
            if any(
                not _is_legacy_scalar(name) or name is None or not _is_legacy_scalar(value)
                for name, value in attributes.items()
            ):
                raise _error(
                    ctx,
                    "unsupported_type",
                    f"{path}.resource.attributes",
                    "use scalar resource attribute names and values",
                )
    if "span_filter" not in source:
        return
    if not allow_span_filter:
        raise _error(ctx, "unsupported_v7_shape", f"{path}.span_filter", "move the filter to a named destination")
    span_filter = _mapping(source["span_filter"], f"{path}.span_filter", ctx)
    _reject_unknown(span_filter, _V7_SPAN_FILTER_KEYS, f"{path}.span_filter", ctx)
    _optional_string(span_filter, "require_operation", f"{path}.span_filter.require_operation", ctx)
    top_attributes: tuple[str, ...] = ()
    if "require_attributes" in span_filter:
        _string_sequence(span_filter["require_attributes"], f"{path}.span_filter.require_attributes", ctx)
        top_attributes = _normalized_span_filter_attributes(
            span_filter["require_attributes"], f"{path}.span_filter.require_attributes", ctx
        )
    if "operations" in span_filter:
        operations = _sequence(span_filter["operations"], f"{path}.span_filter.operations", ctx)
        if operations and (_first_nonempty_text(span_filter.get("require_operation")) or top_attributes):
            raise _error(
                ctx,
                "unsupported_span_filter",
                f"{path}.span_filter",
                "do not mix operation entries with top-level span-filter predicates",
            )
        seen_operations: set[str] = set()
        for index, operation_value in enumerate(operations):
            operation_path = f"{path}.span_filter.operations[{index}]"
            operation = _mapping(operation_value, operation_path, ctx)
            _reject_unknown(operation, _V7_SPAN_FILTER_OPERATION_KEYS, operation_path, ctx)
            _optional_string(operation, "name", f"{operation_path}.name", ctx)
            operation_name = _first_nonempty_text(operation.get("name"))
            if not operation_name:
                raise _error(ctx, "unsupported_span_filter", operation_path, "name every span-filter operation")
            if operation_name in seen_operations:
                raise _error(ctx, "unsupported_span_filter", operation_path, "remove duplicate span-filter operations")
            seen_operations.add(operation_name)
            if "require_attributes" in operation:
                _string_sequence(operation["require_attributes"], f"{operation_path}.require_attributes", ctx)
                _normalized_span_filter_attributes(
                    operation["require_attributes"], f"{operation_path}.require_attributes", ctx
                )


def _validate_sink(sink: Mapping[str, Any], path: str, ctx: _Context) -> None:
    _reject_unknown(sink, _V7_SINK_KEYS, path, ctx)
    _optional_bool(sink, "enabled", f"{path}.enabled", ctx)
    _optional_string(sink, "name", f"{path}.name", ctx)
    _optional_string(sink, "kind", f"{path}.kind", ctx)
    for key in ("batch_size", "flush_interval_s", "timeout_s"):
        _optional_int(sink, key, f"{path}.{key}", ctx)
    _optional_string(sink, "min_severity", f"{path}.min_severity", ctx)
    if "actions" in sink:
        _string_sequence(sink["actions"], f"{path}.actions", ctx)
    kind = sink.get("kind")
    blocks = {name for name in ("splunk_hec", "otlp_logs", "http_jsonl") if name in sink}
    if kind not in blocks or len(blocks) != 1:
        raise _error(ctx, "unsupported_audit_sink", path, "set one kind-matching audit sink block")
    block = _mapping(sink[kind], f"{path}.{kind}", ctx)
    allowed = {
        "splunk_hec": {
            "endpoint",
            "token",
            "token_env",
            "index",
            "source",
            "sourcetype",
            "verify_tls",
            "insecure_skip_verify",
            "sourcetype_overrides",
        },
        "otlp_logs": {"endpoint", "protocol", "url_path", "headers", "insecure", "ca_cert", "logger_name"},
        "http_jsonl": {
            "url",
            "method",
            "headers",
            "bearer_env",
            "bearer_token",
            "verify_tls",
            "insecure_skip_verify",
        },
    }[str(kind)]
    _reject_unknown(block, frozenset(allowed), f"{path}.{kind}", ctx)
    for boolean_key in ("verify_tls", "insecure_skip_verify", "insecure"):
        _optional_bool(block, boolean_key, f"{path}.{kind}.{boolean_key}", ctx)
    for string_key in allowed - {"sourcetype_overrides", "headers"}:
        if string_key not in {"verify_tls", "insecure_skip_verify", "insecure"}:
            _optional_string(block, string_key, f"{path}.{kind}.{string_key}", ctx)
    for mapping_key in ("headers", "sourcetype_overrides"):
        if mapping_key in block:
            mapping = _mapping(block[mapping_key], f"{path}.{kind}.{mapping_key}", ctx)
            if any(not isinstance(name, str) or not isinstance(value, str) for name, value in mapping.items()):
                raise _error(
                    ctx,
                    "unsupported_type",
                    f"{path}.{kind}.{mapping_key}",
                    "use string mapping keys and values",
                )


def _build_observability(
    document: Mapping[str, Any], profile: str, effective_data_dir: str | None, ctx: _Context
) -> tuple[dict[str, Any], int, int, str]:
    result: dict[str, Any] = {}
    data_dir = _resolve_effective_data_dir(document, effective_data_dir, ctx)
    ctx.effective_data_dir = data_dir
    otel = _mapping(document.get("otel"), "$.otel", ctx) if "otel" in document else {}
    ai_discovery = _mapping(document.get("ai_discovery"), "$.ai_discovery", ctx) if "ai_discovery" in document else {}
    ai_otel = ai_discovery.get("emit_otel", True)
    if type(ai_otel) is not bool:
        raise _error(ctx, "unsupported_type", "$.ai_discovery.emit_otel", "use true or false")

    # These identities are created implicitly by v8. Reserve them before any
    # migrated destination claims a name so valid v7 collisions receive a
    # deterministic suffix instead of failing canonical compilation.
    ctx.used_names.update({"local-sqlite", "gateway-jsonl", "gateway-console"})

    if resource := _resource_attributes(otel, ctx):
        result["resource"] = {"attributes": resource}
    result["trace_policy"] = _trace_policy(otel, ctx)
    master_enabled = _effective_otel_enabled(otel, ctx)
    flat_otel_destination = _flat_otel_destination(otel, ctx)
    metric_policy = _metric_policy(otel, master_enabled, flat_otel_destination, ctx)
    if metric_policy:
        result["metric_policy"] = metric_policy

    otlp_destinations, active_otel_signals, local_state = _convert_otel(
        otel,
        master_enabled,
        profile,
        ai_otel,
        flat_otel_destination,
        ctx,
    )
    defaults: dict[str, Any] = {
        "collect": {signal: False for signal in _SIGNALS},
    }
    if profile != "none":
        defaults["redaction_profile"] = profile
    result["defaults"] = defaults
    effective_collection = ctx.compatibility_selection.effective_collection(active_otel_signals)
    if not ai_otel:
        # ``emit_otel: false`` disabled the legacy AI-discovery OTel path. Keep
        # only any independently required always-collected AI-discovery signal;
        # conditional OTel collection must not survive after its routes become
        # explicit drops.
        effective_collection = {
            signal: tuple(
                bucket
                for bucket in effective_collection[signal]
                if bucket != "ai.discovery"
                or bucket in ctx.compatibility_selection.collection_buckets("always", signal)
            )
            for signal in _SIGNALS
        }
    bucket_policies: dict[str, Any] = {}
    for bucket in BUCKETS:
        enabled = {signal: True for signal in _SIGNALS if bucket in effective_collection[signal]}
        if enabled:
            bucket_policies[bucket] = {"collect": enabled}
    if bucket_policies:
        result["buckets"] = bucket_policies

    local: dict[str, Any] = {
        "path": str(Path(data_dir) / "audit.db"),
        "judge_bodies_path": str(Path(data_dir) / "judge_bodies.db"),
    }
    if "audit_db" in document:
        local["path"] = document["audit_db"]
    if "judge_bodies_db" in document:
        local["judge_bodies_path"] = document["judge_bodies_db"]
    result["local"] = local

    connectors, connector_sink_configs = _legacy_connectors(document, ctx)
    if connectors:
        result["connectors"] = connectors

    destinations: list[dict[str, Any]] = []
    jsonl: dict[str, Any] = {
        "name": "gateway-jsonl",
        "kind": "jsonl",
        "path": str(Path(data_dir) / "gateway.jsonl"),
        "rotation": {"max_size_mb": 50, "max_backups": 5, "max_age_days": 30, "compress": True},
        "routes": _exporter_routes(ctx, "gateway_jsonl", ("logs",), profile, "legacy-jsonl"),
    }
    if _environment_true(ctx.environment.get("DEFENSECLAW_JSONL_DISABLE", ""), _JSONL_DISABLE_TRUE):
        jsonl["enabled"] = False
        ctx.warning("environment_decision:DEFENSECLAW_JSONL_DISABLE")
    destinations.append(jsonl)
    destinations.append(
        {
            "name": "gateway-console",
            "kind": "console",
            "routes": _exporter_routes(ctx, "gateway_console", ("logs",), profile, "legacy-console"),
        }
    )
    destinations.extend(otlp_destinations)
    global_sinks = [
        _mapping(value, f"$.audit_sinks[{index}]", ctx)
        for index, value in enumerate(
            _sequence(document.get("audit_sinks"), "$.audit_sinks", ctx) if "audit_sinks" in document else []
        )
    ]
    audit_destinations = _convert_audit_sinks(global_sinks, connector_sink_configs, profile, ctx)
    destinations.extend(audit_destinations)
    result["destinations"] = destinations

    return result, len(otlp_destinations), len(audit_destinations), local_state


def _resolve_effective_data_dir(document: Mapping[str, Any], effective_data_dir: str | None, ctx: _Context) -> str:
    configured = document.get("data_dir")
    if configured is not None and (not isinstance(configured, str) or not configured):
        raise _error(ctx, "unsupported_type", "$.data_dir", "use a nonempty path string")
    resolved = configured if isinstance(configured, str) and Path(configured).is_absolute() else effective_data_dir
    if not isinstance(resolved, str) or not Path(resolved).is_absolute():
        raise V8MigrationDependencyError(
            "effective_data_dir_required",
            "$.data_dir",
            "supply the absolute v7 effective data directory from the upgrader",
            source_name=ctx.source_name,
        )
    return os.path.abspath(resolved)


def _resource_attributes(otel: Mapping[str, Any], ctx: _Context) -> dict[str, str]:
    """Canonicalize registered v7 identity while preserving custom attributes.

    V7 stored process-owned identity, destination-preset markers, and operator
    attributes in one open map. V8 keeps one resource map but classifies known
    registered keys separately from custom extras. An unsupported reserved key
    must stop the upgrade instead of being silently copied or renamed.
    """

    resource = _mapping(otel.get("resource"), "$.otel.resource", ctx) if "resource" in otel else {}
    attrs = (
        _mapping(resource.get("attributes"), "$.otel.resource.attributes", ctx)
        if resource.get("attributes") is not None
        else {}
    )
    normalized: dict[str, str] = {}
    for name, value in attrs.items():
        if not _is_legacy_scalar(name) or name is None or not _is_legacy_scalar(value):
            raise _error(ctx, "unsupported_type", "$.otel.resource.attributes", "use scalar keys and values")
        normalized_name = _legacy_scalar_text(name)
        if value is not None:
            normalized[normalized_name] = _legacy_scalar_text(value)

    if service_name := ctx.environment.get("OTEL_SERVICE_NAME", ""):
        normalized["service.name"] = service_name
        ctx.warning("environment_decision:OTEL_SERVICE_NAME")

    canonical_environment = normalized.get("deployment.environment.name")
    legacy_environment = normalized.get("deployment.environment")
    if (
        canonical_environment is not None
        and legacy_environment is not None
        and canonical_environment != legacy_environment
    ):
        raise _error(
            ctx,
            "conflicting_resource_environment",
            "$.otel.resource.attributes",
            "make deployment.environment.name and deployment.environment exactly equal before upgrading",
        )
    environment = canonical_environment if canonical_environment is not None else legacy_environment
    result: dict[str, str] = {}
    environment_written = False
    for name, value in normalized.items():
        if name == "service.name":
            result[name] = value
            ctx.resource_migration("service_name_preserved")
            continue
        if name in {"deployment.environment.name", "deployment.environment"}:
            if not environment_written and environment is not None:
                result["deployment.environment.name"] = environment
                environment_written = True
                ctx.resource_migration("environment_canonicalized")
                if canonical_environment is not None and legacy_environment is not None:
                    ctx.resource_migration("environment_aliases_coalesced")
            continue
        if name == "defenseclaw.preset":
            ctx.resource_migration("preset_identity_consumed")
            continue
        if name == "defenseclaw.preset_name":
            ctx.resource_migration("preset_display_name_removed")
            continue
        if name in RESERVED_RESOURCE_ATTRIBUTE_KEYS and name not in CONFIGURABLE_CORE_RESOURCE_ATTRIBUTE_KEYS:
            raise _error(
                ctx,
                "unsupported_reserved_resource_attribute",
                f"$.otel.resource.attributes.{name}",
                "remove this process-owned resource key; DefenseClaw derives it in v8",
            )
        result[name] = value
    return result


def _trace_policy(otel: Mapping[str, Any], ctx: _Context) -> dict[str, str]:
    """Translate the deliberately small v7 sampler implementation semantically.

    V7 recognizes only ``always_off`` and ``parentbased_traceidratio``;
    every other name (including an omitted name) is AlwaysSample. Copying the
    newer v8 sampler vocabulary verbatim would therefore change decisions.
    """

    traces = _mapping(otel.get("traces"), "$.otel.traces", ctx) if "traces" in otel else {}
    sampler = traces.get("sampler")
    if sampler == "always_off":
        return {"sampler": "always_off"}
    if sampler != "parentbased_traceidratio":
        if sampler not in (None, "", "always_on"):
            ctx.warning("legacy_sampler_normalized_to_always_on")
        return {"sampler": "always_on"}

    raw_argument = traces.get("sampler_arg", "1.0")
    if not isinstance(raw_argument, str):
        raise _error(ctx, "unsupported_type", "$.otel.traces.sampler_arg", "use text")
    try:
        ratio = float(raw_argument)
    except ValueError:
        ratio = 1.0
        ctx.warning("legacy_sampler_argument_normalized")
    if math.isnan(ratio):
        ratio = 1.0
        ctx.warning("legacy_sampler_argument_normalized")
    ratio = max(0.0, min(1.0, ratio))
    return {"sampler": "parentbased_traceidratio", "sampler_arg": str(ratio)}


def _metric_policy(
    otel: Mapping[str, Any],
    master_enabled: bool,
    flat_destination: Mapping[str, Any] | None,
    ctx: _Context,
) -> dict[str, Any]:
    metrics = _mapping(otel.get("metrics"), "$.otel.metrics", ctx) if "metrics" in otel else {}
    global_interval = _legacy_positive_or_default(
        metrics.get("export_interval_s"), 60, "$.otel.metrics.export_interval_s", ctx
    )
    global_temporality = _legacy_temporality(metrics.get("temporality"), "$.otel.metrics.temporality", ctx)
    intervals: dict[int, list[str]] = {}
    temporalities: dict[str, list[str]] = {}
    if flat_destination is not None:
        flat_metrics = _mapping(flat_destination.get("metrics"), "$.otel.metrics", ctx)
        if master_enabled and flat_destination.get("enabled") is True and flat_metrics.get("enabled") is True:
            intervals.setdefault(global_interval, []).append("$.otel.metrics.export_interval_s")
            temporalities.setdefault(global_temporality, []).append("$.otel.metrics.temporality")
    for index, raw in enumerate(otel.get("destinations", []) or []):
        destination = _mapping(raw, f"$.otel.destinations[{index}]", ctx)
        signal = (
            _mapping(destination.get("metrics"), f"$.otel.destinations[{index}].metrics", ctx)
            if "metrics" in destination
            else {}
        )
        if master_enabled and destination.get("enabled") is True and signal.get("enabled") is True:
            raw_name = destination.get("name")
            safe_name = raw_name if isinstance(raw_name, str) and _NAME_RE.fullmatch(raw_name) else str(index)
            prefix = f"$.otel.destinations[{safe_name}].metrics"
            interval = _legacy_positive_or_default(
                signal.get("export_interval_s"), global_interval, f"{prefix}.export_interval_s", ctx
            )
            temporality = _legacy_temporality(
                signal.get("temporality"), f"{prefix}.temporality", ctx, default=global_temporality
            )
            intervals.setdefault(interval, []).append(f"{prefix}.export_interval_s")
            temporalities.setdefault(temporality, []).append(f"{prefix}.temporality")
    if len(intervals) > 1 or len(temporalities) > 1:
        conflicting = intervals if len(intervals) > 1 else temporalities
        paths = [path for grouped in conflicting.values() for path in grouped]
        raise _error(
            ctx,
            "conflicting_metric_policy",
            " <-> ".join(paths),
            "align policies or keep only one metric-export destination",
        )
    return {
        "export_interval_seconds": next(iter(intervals), global_interval),
        "temporality": next(iter(temporalities), global_temporality),
    }


def _legacy_connectors(
    document: Mapping[str, Any], ctx: _Context
) -> tuple[dict[str, Any], dict[str, list[Mapping[str, Any]]]]:
    obs = _mapping(document.get("observability"), "$.observability", ctx) if "observability" in document else {}
    raw_connectors = _mapping(obs.get("connectors"), "$.observability.connectors", ctx) if "connectors" in obs else {}
    connectors: dict[str, Any] = {}
    sink_configs: dict[str, list[Mapping[str, Any]]] = {}
    for name, raw in raw_connectors.items():
        normalized_name = _normalize_legacy_connector_name(name)
        if normalized_name != name:
            ctx.warning(f"connector_name_normalized:{normalized_name}")
        source = _mapping(raw, f"$.observability.connectors.{name}", ctx)
        target: dict[str, Any] = {}
        if "webhooks" in source:
            target["webhooks"] = copy.deepcopy(source["webhooks"])
        if target:
            connectors[normalized_name] = target
        if "audit_sinks" in source:
            sink_configs[normalized_name] = [
                _mapping(item, f"$.observability.connectors.{name}.audit_sinks[{index}]", ctx)
                for index, item in enumerate(_sequence(source["audit_sinks"], "audit_sinks", ctx))
            ]
    return connectors, sink_configs


def _convert_otel(
    otel: Mapping[str, Any],
    master_enabled: bool,
    profile: str,
    ai_otel: bool,
    flat_destination: Mapping[str, Any] | None,
    ctx: _Context,
) -> tuple[list[dict[str, Any]], tuple[str, ...], str]:
    raw_destinations = list(otel.get("destinations", []) or [])
    if flat_destination is not None:
        raw_destinations.insert(0, flat_destination)
    if master_enabled and not raw_destinations:
        raise _error(
            ctx,
            "invalid_v7_otel",
            "$.otel.destinations",
            "configure at least one named or flat OTel destination before upgrading",
        )
    logs = _mapping(otel.get("logs"), "$.otel.logs", ctx) if "logs" in otel else {}
    findings = logs.get("emit_individual_findings") is True
    result: list[dict[str, Any]] = []
    active_signals: set[str] = set()
    local_coverage: list[bool] = []
    global_batch = _mapping(otel.get("batch"), "$.otel.batch", ctx) if "batch" in otel else {}
    effective_global_batch = _effective_otel_batch(global_batch, {}, "$.otel.batch", ctx)
    for index, raw in enumerate(raw_destinations):
        source = dict(_mapping(raw, f"$.otel.destinations[{index}]", ctx))
        destination_batch = (
            _mapping(source.get("batch"), f"$.otel.destinations[{index}].batch", ctx) if "batch" in source else {}
        )
        source["__scheduled_delay_explicit"] = (
            _legacy_positive_value(destination_batch.get("scheduled_delay_ms")) is not None
            or _legacy_positive_value(global_batch.get("scheduled_delay_ms")) is not None
        )
        source["batch"] = _effective_otel_batch(
            destination_batch,
            effective_global_batch,
            f"$.otel.destinations[{index}].batch",
            ctx,
        )
        converted, active, local_full = _convert_otel_destination(
            source, master_enabled, findings, ai_otel, profile, index, ctx
        )
        result.extend(converted)
        active_signals.update(active)
        if local_full is not None:
            local_coverage.append(local_full)
    local_state = "not-configured"
    if local_coverage:
        local_state = "full" if all(local_coverage) else "partial"
        if local_state == "partial":
            ctx.warning("partial_dashboard_capability:local-observability")
    return result, tuple(signal for signal in _SIGNALS if signal in active_signals), local_state


def _flat_otel_destination(otel: Mapping[str, Any], ctx: _Context) -> dict[str, Any] | None:
    has_flat = any(key in otel for key in ("endpoint", "protocol", "headers", "tls")) or any(
        any(
            key in _mapping(otel.get(signal), f"$.otel.{signal}", ctx)
            for key in ("enabled", "endpoint", "protocol", "url_path")
        )
        for signal in _SIGNALS
        if signal in otel
    )
    environment_endpoint = _first_env(
        ctx.environment,
        "DEFENSECLAW_OTEL_ENDPOINT",
        "OPENCLAW_OTEL_ENDPOINT",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
    )
    global_endpoint = _first_nonempty_text(otel.get("endpoint"), environment_endpoint)
    if environment_endpoint and not _first_nonempty_text(otel.get("endpoint")):
        ctx.warning("environment_decision:OTEL_ENDPOINT")
    signal_sources = {
        signal: _mapping(otel.get(signal), f"$.otel.{signal}", ctx) if signal in otel else {} for signal in _SIGNALS
    }
    environment_signal_endpoints = {
        signal: _first_env(
            ctx.environment,
            f"DEFENSECLAW_OTEL_{signal.upper()}_ENDPOINT",
            f"OPENCLAW_OTEL_{signal.upper()}_ENDPOINT",
            f"OTEL_EXPORTER_OTLP_{signal.upper()}_ENDPOINT",
        )
        for signal in _SIGNALS
    }
    signal_endpoints = {
        signal: _first_nonempty_text(signal_sources[signal].get("endpoint"), environment_signal_endpoints[signal])
        for signal in _SIGNALS
    }
    if not has_flat and not (global_endpoint or any(signal_endpoints.values())):
        return None
    resource = _mapping(otel.get("resource"), "$.otel.resource", ctx) if "resource" in otel else {}
    attributes = (
        _mapping(resource.get("attributes"), "$.otel.resource.attributes", ctx) if "attributes" in resource else {}
    )
    preset_raw = attributes.get("defenseclaw.preset", "generic-otlp")
    if not _is_legacy_scalar(preset_raw) or preset_raw is None:
        raise _error(ctx, "unsupported_type", "$.otel.resource.attributes.defenseclaw.preset", "use text")
    preset = _legacy_scalar_text(preset_raw)
    if not preset:
        raise _error(ctx, "unsupported_type", "$.otel.resource.attributes.defenseclaw.preset", "use text")
    configured_names = {
        _first_nonempty_text(_mapping(raw, "$.otel.destinations[]", ctx).get("name"))
        for raw in otel.get("destinations", []) or []
    }
    flat_name = "generic-otlp"
    suffix = 2
    while flat_name in configured_names:
        flat_name = f"generic-otlp-{suffix}"
        suffix += 1
    name = "local-observability" if preset == "local-otlp" else (flat_name if preset == "generic-otlp" else preset)
    configured_endpoints = [endpoint for endpoint in (global_endpoint, *signal_endpoints.values()) if endpoint]
    if (
        preset == "generic-otlp"
        and configured_endpoints
        and all(_endpoint_is_loopback(endpoint, ctx) for endpoint in configured_endpoints)
    ):
        preset = "local-otlp"
        name = "local-observability"
    environment_protocol = _first_env(
        ctx.environment,
        "DEFENSECLAW_OTEL_PROTOCOL",
        "OPENCLAW_OTEL_PROTOCOL",
        "OTEL_EXPORTER_OTLP_PROTOCOL",
    )
    global_protocol = _first_nonempty_text(otel.get("protocol"), environment_protocol)
    if environment_protocol and not _first_nonempty_text(otel.get("protocol")):
        ctx.warning("environment_decision:OTEL_PROTOCOL")
    environment_signal_protocols = {
        signal: _first_env(
            ctx.environment,
            f"DEFENSECLAW_OTEL_{signal.upper()}_PROTOCOL",
            f"OPENCLAW_OTEL_{signal.upper()}_PROTOCOL",
            f"OTEL_EXPORTER_OTLP_{signal.upper()}_PROTOCOL",
        )
        for signal in _SIGNALS
    }
    signal_protocols = {
        signal: _first_nonempty_text(signal_sources[signal].get("protocol"), environment_signal_protocols[signal])
        for signal in _SIGNALS
    }
    inherited_protocol = _first_nonempty_text(
        global_protocol,
        signal_protocols["traces"],
        signal_protocols["logs"],
        signal_protocols["metrics"],
        "grpc",
    )
    source: dict[str, Any] = {
        "__flat_otel_destination": True,
        "name": name,
        "preset": preset,
        "enabled": _effective_otel_enabled(otel, ctx),
        "endpoint": global_endpoint,
        # V7's synthesized flat destination lets the first configured signal
        # protocol become the destination fallback for every other signal.
        "protocol": inherited_protocol,
    }
    for key in ("headers", "tls", "batch"):
        if key in otel:
            source[key] = copy.deepcopy(otel[key])
    tls_insecure = (
        _first_env(
            ctx.environment,
            "DEFENSECLAW_OTEL_TLS_INSECURE",
            "OPENCLAW_OTEL_TLS_INSECURE",
        )
        .strip()
        .lower()
    )
    if "tls" not in source or "insecure" not in _mapping(source["tls"], "$.otel.tls", ctx):
        if tls_insecure in _TLS_TRUE | _TLS_FALSE:
            source.setdefault("tls", {})["insecure"] = tls_insecure in _TLS_TRUE
            ctx.warning("environment_decision:DEFENSECLAW_OTEL_TLS_INSECURE")
    explicit = any(isinstance(otel.get(signal), Mapping) and "enabled" in otel[signal] for signal in _SIGNALS)
    for signal in _SIGNALS:
        signal_source = copy.deepcopy(dict(signal_sources[signal]))
        if environment_signal_endpoints[signal] and not _first_nonempty_text(signal_sources[signal].get("endpoint")):
            ctx.warning(f"environment_decision:OTEL_{signal.upper()}_ENDPOINT")
        if signal_endpoints[signal]:
            signal_source["endpoint"] = signal_endpoints[signal]
        else:
            signal_source.pop("endpoint", None)
        if environment_signal_protocols[signal] and not _first_nonempty_text(signal_sources[signal].get("protocol")):
            ctx.warning(f"environment_decision:OTEL_{signal.upper()}_PROTOCOL")
        if signal_protocols[signal]:
            signal_source["protocol"] = signal_protocols[signal]
        else:
            signal_source.pop("protocol", None)
        if "enabled" not in signal_source and (
            signal_source.get("endpoint") or signal_source.get("url_path") or (global_endpoint and not explicit)
        ):
            signal_source["enabled"] = True
        source[signal] = signal_source
    if source.get("endpoint") and not any(source[signal].get("enabled") is True for signal in _SIGNALS):
        for signal in _SIGNALS:
            source[signal]["enabled"] = True
    return source


def _convert_otel_destination(
    source: Mapping[str, Any],
    master_enabled: bool,
    findings: bool,
    ai_otel: bool,
    profile: str,
    index: int,
    ctx: _Context,
) -> tuple[list[dict[str, Any]], tuple[str, ...], bool | None]:
    path = f"$.otel.destinations[{index}]"
    raw_name = source.get("name", "")
    base_name = _normalize_destination_name(raw_name, f"{path}.name", ctx)
    preset = source.get("preset", "")
    if preset == "local-otlp" or base_name == "local-observability":
        base_name = "local-observability"
    is_local = base_name == "local-observability"
    is_galileo = preset == "galileo" or base_name == "galileo"
    span_filter = _mapping(source.get("span_filter"), f"{path}.span_filter", ctx) if "span_filter" in source else {}
    span_filter_enabled = _legacy_span_filter_enabled(span_filter)
    custom_trace_selectors = (
        _span_filter_selectors(span_filter, is_galileo, ctx, f"{path}.span_filter") if span_filter_enabled else None
    )

    enabled_signals: list[str] = []
    signals: dict[str, Mapping[str, Any]] = {}
    for signal in _SIGNALS:
        value = _mapping(source.get(signal), f"{path}.{signal}", ctx) if signal in source else {}
        signals[signal] = value
        if value.get("enabled") is True:
            enabled_signals.append(signal)
    is_flat = source.get("__flat_otel_destination") is True
    tls_parent_path = "$.otel" if is_flat else path
    if not enabled_signals and is_flat and source.get("endpoint"):
        enabled_signals = list(_SIGNALS)
    if source.get("enabled") is True and not enabled_signals:
        raise _error(
            ctx,
            "invalid_v7_otel",
            path,
            "enable at least one signal on the named destination before upgrading",
        )
    if source.get("enabled") is True:
        for signal in enabled_signals:
            if not source.get("endpoint") and not signals[signal].get("endpoint"):
                raise _error(
                    ctx,
                    "invalid_v7_otel",
                    f"{path}.{signal}.endpoint",
                    "configure an endpoint for every enabled signal before upgrading",
                )

    active_signals = tuple(
        signal for signal in _SIGNALS if master_enabled and source.get("enabled") is True and signal in enabled_signals
    )
    local_full: bool | None = None
    if is_local:
        local_full = (
            ctx.compatibility_selection.local_observability.complete
            and set(active_signals) == set(_SIGNALS)
            and not span_filter_enabled
            and ai_otel
        )

    dormant = not enabled_signals
    if dormant:
        # V7 permits a disabled destination with no enabled signals. V8 has no
        # empty signal selection, so retain every configured transport behind
        # an explicit catch-all drop route. A destination with no endpoint at
        # all has no valid v8 transport representation and must fail rather
        # than silently disappear.
        enabled_signals = [signal for signal in _SIGNALS if source.get("endpoint") or signals[signal].get("endpoint")]
        if not enabled_signals:
            raise _error(
                ctx,
                "dormant_otel_not_representable",
                path,
                "add an endpoint and explicit signal or remove the disabled destination before upgrading",
            )

    global_protocol = _protocol(source.get("protocol") or ("http/protobuf" if is_galileo else "grpc"), path, ctx)
    source_tls = _tls(source.get("tls", {}), tls_parent_path, ctx)
    if source_tls.pop("insecure_skip_verify", None) is not None:
        ctx.warning(f"legacy_otlp_insecure_skip_verify_ignored:{base_name}")
    configured_insecure = source_tls.get("insecure") is True
    ca_cert = source_tls.get("ca_cert", "")
    if ca_cert and not Path(ca_cert).is_absolute():
        raise _error(
            ctx,
            "relative_v7_otel_ca_cert",
            f"{tls_parent_path}.tls.ca_cert",
            "replace the legacy OTLP CA certificate with an absolute path before upgrading",
        )
    by_transport: dict[tuple[str, bool], list[str]] = {}
    for signal in enabled_signals:
        protocol = _protocol(signals[signal].get("protocol") or global_protocol, f"{path}.{signal}.protocol", ctx)
        resolved_endpoint = signals[signal].get("endpoint") or source.get("endpoint")
        insecure = _legacy_otlp_endpoint_insecure(
            resolved_endpoint,
            protocol,
            configured_insecure,
            ca_cert,
        )
        by_transport.setdefault((protocol, insecure), []).append(signal)
    groups: list[tuple[str, list[str], bool, bool]] = []
    global_insecure = _legacy_otlp_endpoint_insecure(
        source.get("endpoint"),
        global_protocol,
        configured_insecure,
        ca_cert,
    )

    def ordered_transport_keys() -> list[tuple[str, bool]]:
        keys = list(by_transport)
        global_key = (global_protocol, global_insecure)
        if source.get("endpoint") and global_key in by_transport:
            keys.remove(global_key)
            return [global_key, *keys]
        return [item for item in keys if item[0] == global_protocol] + [
            item for item in keys if item[0] != global_protocol
        ]

    if is_galileo and "traces" in enabled_signals:
        trace_protocol = _protocol(signals["traces"].get("protocol") or global_protocol, f"{path}.traces.protocol", ctx)
        trace_endpoint = signals["traces"].get("endpoint") or source.get("endpoint")
        trace_insecure = _legacy_otlp_endpoint_insecure(
            trace_endpoint,
            trace_protocol,
            configured_insecure,
            ca_cert,
        )
        groups.append((trace_protocol, ["traces"], True, trace_insecure))
        for protocol, insecure in ordered_transport_keys():
            non_trace = [signal for signal in by_transport[(protocol, insecure)] if signal != "traces"]
            if non_trace:
                groups.append((protocol, non_trace, False, insecure))
    else:
        for protocol, insecure in ordered_transport_keys():
            groups.append((protocol, by_transport[(protocol, insecure)], False, insecure))

    if is_local:
        # The runtime binds the local-observability-v1 trace projection to the
        # reserved destination name.  V7 signal-specific protocols may split a
        # destination, so keep the trace-bearing group on that exact name and
        # suffix only its generic log/metric siblings.  Stable partitioning
        # preserves the existing protocol order for all non-trace groups.
        groups = [group for group in groups if "traces" in group[1]] + [
            group for group in groups if "traces" not in group[1]
        ]

    split = len(groups) > 1
    result: list[dict[str, Any]] = []
    for group_index, (protocol, group, galileo_group, insecure) in enumerate(groups):
        suffix = "-" + "-".join(group) if split and group_index > 0 else ""
        name = _unique_name(_bounded_name(base_name + suffix), ctx)
        target: dict[str, Any] = {"name": name, "kind": "otlp", "protocol": protocol}
        if not (master_enabled and source.get("enabled") is True):
            target["enabled"] = False
        if galileo_group:
            target["preset"] = "galileo"
        endpoint = source.get("endpoint")
        group_endpoint = ""
        if endpoint and _legacy_otlp_endpoint_insecure(endpoint, protocol, configured_insecure, ca_cert) == insecure:
            group_endpoint, _ = _normalize_legacy_otlp_endpoint(endpoint, protocol, insecure)
            target["endpoint"] = _text(group_endpoint, f"{path}.endpoint", ctx)
        headers = _convert_headers(source.get("headers", {}), name, ctx)
        if headers:
            target["headers"] = headers
        tls = copy.deepcopy(source_tls)
        if insecure:
            if tls.get("ca_cert"):
                group_active = any(signal in active_signals for signal in group)
                if protocol.startswith("grpc") or not group_active:
                    tls.pop("ca_cert", None)
                    ctx.warning(f"legacy_plaintext_otlp_ca_ignored:{name}")
                else:
                    raise _error(
                        ctx,
                        "conflicting_v7_otel_tls",
                        f"{tls_parent_path}.tls.ca_cert",
                        "remove ca_cert or use only TLS-secured OTLP endpoints before upgrading",
                    )
            tls["insecure"] = True
        if tls:
            target["tls"] = tls
        if batch := _batch(source.get("batch", {}), path, ctx):
            target["batch"] = batch
        if galileo_group and not source.get("__scheduled_delay_explicit"):
            target.setdefault("batch", {})["scheduled_delay_ms"] = 1000
            ctx.warning("galileo_preset_delay_changed:5000_to_1000")
        overrides: dict[str, Any] = {}
        for signal in group:
            override: dict[str, Any] = {}
            signal_endpoint = signals[signal].get("endpoint") or endpoint
            normalized_endpoint, endpoint_path = _normalize_legacy_otlp_endpoint(
                signal_endpoint,
                protocol,
                insecure,
            )
            if normalized_endpoint and normalized_endpoint != group_endpoint:
                override["endpoint"] = _text(normalized_endpoint, f"{path}.{signal}.endpoint", ctx)
            raw_url_path = signals[signal].get("url_path")
            if protocol.startswith("http"):
                effective_path = ""
                if raw_url_path:
                    effective_path = _normalize_legacy_otlp_url_path(
                        _text(raw_url_path, f"{path}.{signal}.url_path", ctx)
                    )
                elif endpoint_path:
                    effective_path = endpoint_path
                if effective_path:
                    override["path"] = effective_path
            elif raw_url_path or endpoint_path:
                ctx.warning(f"legacy_grpc_path_ignored:{name}:{signal}")
            if override:
                overrides[signal] = override
        if overrides:
            target["signal_overrides"] = overrides
        _network_safety(target, ctx)

        if dormant:
            target["routes"] = [
                {
                    "name": "legacy-disabled-no-signals",
                    "signals": list(group),
                    "selector": {},
                    "action": "drop",
                }
            ]
            result.append(target)
            continue

        prefix_routes: list[dict[str, Any]] = []
        if not ai_otel:
            prefix_routes.append(
                _raw_route(
                    "legacy-ai-discovery-disabled",
                    tuple(group),
                    {"buckets": ["ai.discovery"]},
                    action="drop",
                )
            )
        if "logs" in group and not findings:
            prefix_routes.extend(
                _selector_routes(
                    ctx.compatibility_selection.feature_selectors("otel_individual_findings"),
                    "logs",
                    profile,
                    "legacy-individual-findings-disabled",
                    action="drop",
                )
            )

        exporter = "local_observability" if is_local else "generic_otlp"
        routes = list(prefix_routes)
        for signal in group:
            selectors = (
                custom_trace_selectors
                if signal == "traces" and custom_trace_selectors is not None
                else ctx.compatibility_selection.exporter_selectors(exporter, signal)
            )
            routes.extend(
                _selector_routes(
                    selectors,
                    signal,
                    profile,
                    f"legacy-{exporter.replace('_', '-')}-{signal}",
                )
            )
        _validate_generated_route_count(routes, path, ctx)
        target["routes"] = routes
        result.append(target)
    return result, active_signals, local_full


def _span_filter_selectors(
    value: Mapping[str, Any],
    is_galileo: bool,
    ctx: _Context,
    path: str,
) -> tuple[V7Selector, ...] | None:
    if not value:
        return None
    if is_galileo and _matches_authoritative_galileo_span_filter(value):
        try:
            selectors = ctx.compatibility_selection.exporter_selectors("galileo", "traces")
        except V7CompatibilityError:
            raise V8MigrationDependencyError(
                "span_filter_mapping_incomplete",
                path,
                "regenerate the exact Galileo exporter compatibility selection",
                source_name=ctx.source_name,
            ) from None
        if not selectors:
            raise V8MigrationDependencyError(
                "span_filter_mapping_incomplete",
                path,
                "regenerate a nonempty Galileo exporter compatibility selection",
                source_name=ctx.source_name,
            )
        return selectors
    predicates: list[tuple[str, Sequence[str]]] = []
    if raw_operations := value.get("operations"):
        for index, raw in enumerate(_sequence(raw_operations, f"{path}.operations", ctx)):
            operation_config = _mapping(raw, f"{path}.operations[{index}]", ctx)
            operation = operation_config.get("name")
            if not isinstance(operation, str) or not operation.strip():
                raise _error(ctx, "unsupported_span_filter", path, "name every legacy filter operation")
            predicates.append(
                (
                    operation.strip(),
                    _normalized_span_filter_attributes(
                        operation_config.get("require_attributes") or [],
                        f"{path}.operations[{index}].require_attributes",
                        ctx,
                    ),
                )
            )
    elif operation := value.get("require_operation"):
        if not isinstance(operation, str):
            raise _error(ctx, "unsupported_span_filter", path, "use a string operation")
        if not operation.strip():
            raise _error(ctx, "unsupported_span_filter", path, "use a nonempty operation")
        predicates.append(
            (
                operation.strip(),
                _normalized_span_filter_attributes(
                    value.get("require_attributes") or [],
                    f"{path}.require_attributes",
                    ctx,
                ),
            )
        )
    if not predicates:
        raise _error(
            ctx,
            "unsupported_span_filter",
            path,
            "use an operation predicate represented by the generated compatibility selection",
        )
    selectors: list[V7Selector] = []
    try:
        for operation, required_attributes in predicates:
            for selector in ctx.compatibility_selection.span_filter_selectors(operation, required_attributes):
                if selector not in selectors:
                    selectors.append(selector)
    except V7CompatibilityError:
        raise V8MigrationDependencyError(
            "span_filter_mapping_incomplete",
            path,
            "regenerate an exact operation and required-attribute compatibility mapping",
            source_name=ctx.source_name,
        ) from None
    if not selectors:
        raise V8MigrationDependencyError(
            "span_filter_mapping_incomplete",
            path,
            "regenerate a nonempty compatibility mapping for the configured span filter",
            source_name=ctx.source_name,
        )
    ctx.warning("span_filter_translated_from_generated_compatibility_selection")
    return tuple(sorted(selectors, key=lambda selector: selector.sort_key))


def _normalized_span_filter_attributes(value: Any, path: str, ctx: _Context) -> tuple[str, ...]:
    attributes: list[str] = []
    seen: set[str] = set()
    for raw in _sequence(value, path, ctx):
        attribute = _text(raw, f"{path}[]", ctx).strip()
        if not attribute:
            raise _error(ctx, "unsupported_span_filter", path, "use nonempty required attribute names")
        if attribute in seen:
            raise _error(ctx, "unsupported_span_filter", path, "remove duplicate required attribute names")
        seen.add(attribute)
        attributes.append(attribute)
    return tuple(attributes)


def _legacy_span_filter_enabled(value: Mapping[str, Any]) -> bool:
    """Mirror v7 ``OTelSpanFilterConfig.Enabled`` after YAML decoding."""

    operation = value.get("require_operation")
    return (
        (isinstance(operation, str) and bool(operation.strip()))
        or bool(value.get("require_attributes"))
        or bool(value.get("operations"))
    )


def _compatibility_query_error(ctx: _Context, path: str) -> V8MigrationDependencyError:
    return V8MigrationDependencyError(
        "compatibility_selection_incomplete",
        path,
        "regenerate the complete v7 exporter compatibility selection",
        source_name=ctx.source_name,
    )


def _matches_authoritative_galileo_span_filter(value: Mapping[str, Any]) -> bool:
    """Recognize the exact historical Galileo v7 preset input shape."""

    if set(value) != {"operations"} or not isinstance(value.get("operations"), list):
        return False
    actual: list[tuple[str, tuple[str, ...]]] = []
    for raw in value["operations"]:
        if not isinstance(raw, Mapping) or set(raw) != {"name", "require_attributes"}:
            return False
        name = raw.get("name")
        attributes = raw.get("require_attributes")
        if not isinstance(name, str) or not isinstance(attributes, list):
            return False
        if any(not isinstance(attribute, str) for attribute in attributes):
            return False
        actual.append((name, tuple(sorted(attributes))))
    expected = [(name, tuple(sorted(attributes))) for name, attributes in _V7_GALILEO_SPAN_FILTER_OPERATIONS]
    return sorted(actual) == sorted(expected)


def _exporter_routes(
    ctx: _Context,
    exporter: str,
    signals: Sequence[str],
    profile: str,
    name_prefix: str,
) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    try:
        for signal in signals:
            routes.extend(
                _selector_routes(
                    ctx.compatibility_selection.exporter_selectors(exporter, signal),
                    signal,
                    profile,
                    f"{name_prefix}-{signal}",
                )
            )
    except V7CompatibilityError:
        raise _compatibility_query_error(ctx, f"$.exporters.{exporter}") from None
    _validate_generated_route_count(routes, f"$.exporters.{exporter}", ctx)
    return routes


def _selector_routes(
    selectors: Sequence[V7Selector],
    signal: str,
    profile: str,
    name_prefix: str,
    *,
    action: str = "send",
) -> list[dict[str, Any]]:
    return [
        _raw_route(
            _bounded_name(f"{name_prefix}-{index + 1}"),
            (signal,),
            _selector_mapping(selector),
            profile=profile,
            action=action,
        )
        for index, selector in enumerate(selectors)
    ]


def _selector_mapping(selector: V7Selector) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for field_name, values in selector.as_mapping().items():
        if len(values) > 256:
            raise V8MigrationDependencyError(
                "compatibility_selector_too_large",
                "$.compatibility_selection",
                "regenerate selectors within the canonical v8 value limit",
            )
        result[field_name] = list(values)
    return result


def _raw_route(
    name: str,
    signals: Sequence[str],
    selector: Mapping[str, Any],
    *,
    profile: str = "none",
    action: str = "send",
) -> dict[str, Any]:
    route: dict[str, Any] = {
        "name": name,
        "signals": list(signals),
        "selector": copy.deepcopy(dict(selector)),
    }
    if action != "send":
        route["action"] = action
    elif set(signals) != {"metrics"}:
        route["redaction_profile"] = profile
    return route


def _audit_selector_routes(
    ctx: _Context,
    *,
    requested_actions: Sequence[str],
    connector: str | None,
    min_severity: str,
    profile: str,
) -> list[dict[str, Any]]:
    try:
        selectors = ctx.compatibility_selection.exporter_selectors("audit_sink", "logs")
    except V7CompatibilityError:
        raise _compatibility_query_error(ctx, "$.exporters.audit_sink") from None
    requested = set(requested_actions)
    routes: list[dict[str, Any]] = []
    for selector in selectors:
        merged: dict[str, Any] = _selector_mapping(selector)
        if requested:
            base_actions = tuple(merged.get("actions", ()))
            # Legacy sink action filters also excluded the separately mirrored
            # gatewaylog.* records.  A selector for those native gateway
            # families therefore cannot survive when an audit-action filter is
            # present; adding the requested action would incorrectly AND an
            # unrelated action onto the event-name selector.
            if not base_actions:
                continue
            actions = tuple(action for action in base_actions if action.strip().casefold() in requested)
            if not actions:
                continue
            merged["actions"] = list(actions)
        if connector:
            merged["connectors"] = [connector]
        if min_severity:
            merged["min_severity"] = min_severity
        routes.append(
            _raw_route(
                _bounded_name(f"legacy-audit-logs-{len(routes) + 1}"),
                ("logs",),
                merged,
                profile=profile,
            )
        )
    return routes


def _validate_generated_route_count(routes: Sequence[Mapping[str, Any]], path: str, ctx: _Context) -> None:
    if not routes or len(routes) > MAX_ROUTES_PER_DESTINATION:
        raise V8MigrationDependencyError(
            "compatibility_route_count_invalid",
            path,
            "regenerate a nonempty compatibility route set within the v8 destination limit",
            source_name=ctx.source_name,
        )
    names = [route.get("name") for route in routes]
    if len(set(names)) != len(names):
        raise V8MigrationDependencyError(
            "compatibility_route_name_collision",
            path,
            "regenerate compatibility routes with unique stable names",
            source_name=ctx.source_name,
        )


def _convert_audit_sinks(
    global_sinks: Sequence[Mapping[str, Any]],
    connector_sinks: Mapping[str, Sequence[Mapping[str, Any]]],
    profile: str,
    ctx: _Context,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    overridden_connectors = sorted(connector_sinks)
    for sink in global_sinks:
        result.append(_convert_sink(sink, profile, ctx, excluded_connectors=overridden_connectors))
    for connector in overridden_connectors:
        configured = connector_sinks[connector]
        for sink in configured:
            result.append(_convert_sink(sink, profile, ctx, only_connector=connector))
    return result


def _convert_sink(
    sink: Mapping[str, Any],
    profile: str,
    ctx: _Context,
    *,
    excluded_connectors: Sequence[str] = (),
    only_connector: str | None = None,
) -> dict[str, Any]:
    name = sink.get("name")
    name = _normalize_destination_name(name, "$.audit_sinks[].name", ctx)
    if only_connector:
        name = _bounded_name(f"{only_connector}-{name}")
    name = _unique_name(name, ctx)
    kind = str(sink["kind"])
    block = _mapping(sink[kind], f"$.audit_sinks[].{kind}", ctx)
    target_kind = "otlp" if kind == "otlp_logs" else kind
    target: dict[str, Any] = {"name": name, "kind": target_kind}
    if sink.get("enabled") is not True:
        target["enabled"] = False
    if kind == "splunk_hec":
        target["endpoint"] = _text(block.get("endpoint"), "$.audit_sinks[].splunk_hec.endpoint", ctx)
        if token_env := block.get("token_env"):
            reference = _env_name(token_env, "$.audit_sinks[].splunk_hec.token_env", ctx)
            inline = block.get("token")
            resolved = ctx.environment.get(reference)
            if resolved:
                ctx.add_sensitive_value(resolved)
            inline_text = _text(inline, "$.audit_sinks[].splunk_hec.token", ctx) if inline else ""
            if inline_text:
                ctx.add_sensitive_value(inline_text)
            if not resolved and inline_text:
                target["token_env"] = _protect_value(
                    name,
                    "token",
                    inline_text,
                    ctx,
                    reference_path=("token_env",),
                )
                ctx.warning("legacy_credential_environment_fallback_promoted")
            else:
                target["token_env"] = reference
        elif token := block.get("token"):
            target["token_env"] = _protect_value(
                name,
                "token",
                _text(token, "token", ctx),
                ctx,
                reference_path=("token_env",),
            )
        for key in ("index",):
            if value := block.get(key):
                target[key] = _text(value, f"$.audit_sinks[].splunk_hec.{key}", ctx)
        target["source"] = _text(block.get("source", "defenseclaw"), "$.audit_sinks[].splunk_hec.source", ctx)
        target["sourcetype"] = _text(block.get("sourcetype", "_json"), "$.audit_sinks[].splunk_hec.sourcetype", ctx)
        target["sourcetype_overrides"] = {
            "llm-judge-response": "defenseclaw:judge",
            "guardrail-verdict": "defenseclaw:verdict",
            **copy.deepcopy(block.get("sourcetype_overrides") or {}),
        }
        if block.get("insecure_skip_verify") is True or (
            "insecure_skip_verify" not in block and block.get("verify_tls") is False
        ):
            target["tls"] = {"insecure_skip_verify": True}
    elif kind == "otlp_logs":
        target["endpoint"] = _text(block.get("endpoint"), "$.audit_sinks[].otlp_logs.endpoint", ctx)
        target["protocol"] = _protocol(block.get("protocol") or "grpc", "$.audit_sinks[].otlp_logs.protocol", ctx)
        if headers := _convert_headers(block.get("headers", {}), name, ctx):
            target["headers"] = headers
        tls: dict[str, Any] = {}
        if block.get("insecure") is True:
            tls["insecure"] = True
        if ca_cert := block.get("ca_cert"):
            tls["ca_cert"] = _text(ca_cert, "$.audit_sinks[].otlp_logs.ca_cert", ctx)
        if tls:
            target["tls"] = tls
        if url_path := block.get("url_path"):
            target["signal_overrides"] = {"logs": {"path": _text(url_path, "url_path", ctx)}}
        target["logger_name"] = _text(
            block.get("logger_name", "defenseclaw.audit"), "$.audit_sinks[].otlp_logs.logger_name", ctx
        )
    else:
        target["endpoint"] = _text(block.get("url"), "$.audit_sinks[].http_jsonl.url", ctx)
        if method := block.get("method"):
            target["method"] = _text(method, "$.audit_sinks[].http_jsonl.method", ctx).upper()
        if headers := _convert_headers(block.get("headers", {}), name, ctx):
            target["headers"] = headers
        if bearer_env := block.get("bearer_env"):
            reference = _env_name(bearer_env, "$.audit_sinks[].http_jsonl.bearer_env", ctx)
            inline = block.get("bearer_token")
            resolved = ctx.environment.get(reference)
            if resolved:
                ctx.add_sensitive_value(resolved)
            inline_text = _text(inline, "$.audit_sinks[].http_jsonl.bearer_token", ctx) if inline else ""
            if inline_text:
                ctx.add_sensitive_value(inline_text)
            if resolved is not None and resolved != "" and not resolved.strip() and sink.get("enabled") is True:
                raise _unrepresentable_bearer(ctx, "$.audit_sinks[].http_jsonl.bearer_env")
            if (resolved is None or resolved == "") and inline_text:
                target["bearer_env"] = _protect_bearer(name, inline_text, ctx)
                ctx.warning("legacy_credential_environment_fallback_promoted")
            elif resolved is not None and resolved.strip():
                target["bearer_env"] = reference
            elif sink.get("enabled") is not True:
                target["bearer_env"] = reference
            else:
                ctx.warning("unresolved_optional_bearer_omitted")
        elif bearer := block.get("bearer_token"):
            target["bearer_env"] = _protect_bearer(name, bearer, ctx)
        if block.get("insecure_skip_verify") is True or (
            "insecure_skip_verify" not in block and block.get("verify_tls") is False
        ):
            target["tls"] = {"insecure_skip_verify": True}
    default_batch = 512 if kind == "otlp_logs" else (50 if kind == "splunk_hec" else 1)
    timeout = _effective_positive_int(sink, "timeout_s", 10, "$.audit_sinks[].timeout_s", ctx)
    target["timeout_ms"] = timeout * 1000
    size = _effective_positive_int(sink, "batch_size", default_batch, "$.audit_sinks[].batch_size", ctx)
    delay = _effective_positive_int(sink, "flush_interval_s", 5, "$.audit_sinks[].flush_interval_s", ctx)
    queue_size = max(2048, size) if kind == "otlp_logs" else max(10_000, size * 100)
    target["batch"] = {
        "max_export_batch_size": size,
        "max_queue_size": queue_size,
        "scheduled_delay_ms": delay * 1000,
    }
    _network_safety(target, ctx)

    routes: list[dict[str, Any]] = []
    if excluded_connectors:
        routes.append(
            {
                "name": "legacy-connector-suppress",
                "signals": ["logs"],
                "selector": {"connectors": sorted(excluded_connectors)},
                "action": "drop",
            }
        )
    requested_actions = ()
    action_filter_blocks_all = False
    if sink.get("actions"):
        requested_actions = tuple(
            dict.fromkeys(
                normalized
                for action in _sequence(sink["actions"], "$.audit_sinks[].actions", ctx)
                if (normalized := _text(action, "$.audit_sinks[].actions[]", ctx).strip().casefold())
            )
        )
        action_filter_blocks_all = not requested_actions
    severity = ""
    if "min_severity" in sink and sink["min_severity"] is not None:
        severity = _legacy_audit_min_severity(_text(sink["min_severity"], "$.audit_sinks[].min_severity", ctx))
    if action_filter_blocks_all:
        routes.append(
            {
                "name": "legacy-empty-action-filter",
                "signals": ["logs"],
                "selector": {},
                "action": "drop",
            }
        )
    else:
        generated = _audit_selector_routes(
            ctx,
            requested_actions=requested_actions,
            connector=only_connector,
            min_severity=severity,
            profile=profile,
        )
        if not generated:
            if requested_actions:
                raise _error(
                    ctx,
                    "unrepresentable_audit_actions",
                    "$.audit_sinks[].actions",
                    "remove the filter or supply an exact generated audit route for every selected action",
                )
            raise _compatibility_query_error(ctx, "$.exporters.audit_sink")
        routes.extend(generated)
    _validate_generated_route_count(routes, "$.audit_sinks[]", ctx)
    target["routes"] = routes
    return target


def _legacy_audit_min_severity(value: str) -> str:
    if value == "":
        return ""
    normalized = value.strip().upper()
    if normalized == "CRITICAL":
        return "CRITICAL"
    if normalized == "HIGH":
        return "HIGH"
    if normalized in {"MEDIUM", "MED"}:
        return "MEDIUM"
    if normalized == "LOW":
        return "LOW"
    # V7 ranks NONE, blank-after-trim, and unknown values as INFO.
    return "INFO"


def _protect_bearer(destination: str, value: Any, ctx: _Context) -> str:
    text = _text(value, "$.audit_sinks[].http_jsonl.bearer_token", ctx)
    if not text.strip():
        raise _unrepresentable_bearer(ctx, "$.audit_sinks[].http_jsonl.bearer_token")
    return _protect_value(
        destination,
        "bearer",
        text,
        ctx,
        reference_path=("bearer_env",),
    )


def _unrepresentable_bearer(ctx: _Context, path: str) -> V8MigrationError:
    return _error(
        ctx,
        "unrepresentable_optional_bearer",
        path,
        "replace the whitespace-only bearer value with a nonempty token or unset it",
    )


def _judge_retention(
    document: Mapping[str, Any], environment: Mapping[str, str], ctx: _Context
) -> tuple[str, bool | None]:
    guardrail = _mapping(document.get("guardrail"), "$.guardrail", ctx) if "guardrail" in document else {}
    explicit = guardrail.get("retain_judge_bodies")
    if explicit is not None and type(explicit) is not bool:
        raise _error(ctx, "unsupported_type", "$.guardrail.retain_judge_bodies", "use true or false")
    env_value = environment.get("DEFENSECLAW_PERSIST_JUDGE", "").strip().lower()
    if env_value in _OFF_LIKE:
        ctx.warning("environment_decision:DEFENSECLAW_PERSIST_JUDGE")
        return "disabled", False
    if explicit is False:
        return "disabled", None
    if explicit is True:
        return "enabled", None
    return "default-enabled", None


def _rewrite_source(
    raw: bytes,
    document: Mapping[str, Any],
    observability: Mapping[str, Any],
    guardrail_value: bool | None,
    ctx: _Context,
) -> bytes:
    text = raw.decode("utf-8")
    newline = "\r\n" if "\r\n" in text else "\n"
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except (yaml.YAMLError, RecursionError, OverflowError):
        raise _error(ctx, "unsafe_source_rewrite", "$", "reduce YAML complexity before upgrading") from None
    if not isinstance(root, MappingNode):
        raise _error(ctx, "invalid_root", "$", "use one YAML mapping")
    pairs = _root_pairs(root)
    pair_by_key = {key.value: (index, key, value) for index, (key, value) in enumerate(pairs)}
    edits: list[tuple[int, int, str]] = []

    if "config_version" in pair_by_key:
        _, _, value = pair_by_key["config_version"]
        edits.append((value.start_mark.index, value.end_mark.index, "8"))
    else:
        insertion = _line_start(text, pairs[0][0].start_mark.index) if pairs else len(text)
        edits.append((insertion, insertion, f"config_version: 8{newline}"))

    owned = ["observability", "otel", "audit_sinks", "audit_db", "judge_bodies_db", "privacy"]
    present = sorted((key for key in owned if key in pair_by_key), key=lambda key: pair_by_key[key][0])
    anchor = "observability" if "observability" in present else (present[0] if present else None)
    rendered_observability = _dump_root_entry("observability", observability, newline)
    if anchor is not None:
        owned_spans = {key: _root_entry_span(text, pairs, pair_by_key[key][0]) for key in present}
        preserved_comments = [
            comment
            for key in present
            for comment in _entry_comments(
                text,
                *owned_spans[key],
                pair_by_key[key][1],
                pair_by_key[key][2],
            )
        ]
        comment_prefix = _render_preserved_comments(preserved_comments, ctx, newline)
        for key in present:
            start, end = owned_spans[key]
            replacement = comment_prefix + rendered_observability if key == anchor else ""
            edits.append((start, end, replacement))
        ctx.warning("modified_observability_sections_reformatted")
    else:
        insertion = len(text)
        prefix = "" if not text or text.endswith(("\n", "\r")) else newline
        edits.append((insertion, insertion, prefix + rendered_observability))

    if "ai_discovery" in pair_by_key and isinstance(document.get("ai_discovery"), Mapping):
        cleaned = {key: copy.deepcopy(value) for key, value in document["ai_discovery"].items() if key != "emit_otel"}
        if cleaned != document["ai_discovery"]:
            index, _, _ = pair_by_key["ai_discovery"]
            start, end = _root_entry_span(text, pairs, index)
            comment_prefix = _render_preserved_comments(
                _entry_comments(text, start, end, pair_by_key["ai_discovery"][1], pair_by_key["ai_discovery"][2]),
                ctx,
                newline,
            )
            edits.append((start, end, comment_prefix + _dump_root_entry("ai_discovery", cleaned, newline)))
            ctx.warning("modified_ai_discovery_section_reformatted")

    if guardrail_value is not None:
        if "guardrail" not in pair_by_key:
            insertion = len(text)
            prefix = "" if not text or text.endswith(("\n", "\r")) else newline
            edits.append(
                (
                    insertion,
                    insertion,
                    prefix + _dump_root_entry("guardrail", {"retain_judge_bodies": guardrail_value}, newline),
                )
            )
        else:
            _, _, guardrail_node = pair_by_key["guardrail"]
            guardrail = document.get("guardrail")
            if isinstance(guardrail_node, MappingNode) and isinstance(guardrail, Mapping):
                pair = _mapping_node_pair(guardrail_node, "retain_judge_bodies")
                if pair is not None:
                    edits.append((pair[1].start_mark.index, pair[1].end_mark.index, "false"))
                elif not guardrail_node.flow_style:
                    insert_at = guardrail_node.end_mark.index
                    indent = guardrail_node.start_mark.column
                    prefix = "" if insert_at == 0 or text[insert_at - 1] in "\r\n" else newline
                    edits.append((insert_at, insert_at, prefix + " " * indent + "retain_judge_bodies: false" + newline))
                else:
                    index, _, _ = pair_by_key["guardrail"]
                    start, end = _root_entry_span(text, pairs, index)
                    replacement = copy.deepcopy(dict(guardrail))
                    replacement["retain_judge_bodies"] = False
                    comment_prefix = _render_preserved_comments(
                        _entry_comments(
                            text,
                            start,
                            end,
                            pair_by_key["guardrail"][1],
                            pair_by_key["guardrail"][2],
                        ),
                        ctx,
                        newline,
                    )
                    edits.append((start, end, comment_prefix + _dump_root_entry("guardrail", replacement, newline)))
                    ctx.warning("modified_guardrail_section_reformatted")
            else:
                raise _error(ctx, "unsupported_guardrail_shape", "$.guardrail", "use a mapping")

    _reject_overlapping_edits(edits, ctx)
    for start, end, replacement in sorted(edits, reverse=True):
        text = text[:start] + replacement + text[end:]
    return _scrub_all_comment_secrets(text, ctx).encode("utf-8")


def _convert_headers(value: Any, context: str, ctx: _Context) -> dict[str, Any]:
    headers = _mapping(value, "headers", ctx) if value else {}
    result: dict[str, Any] = {}
    for name, raw_value in headers.items():
        if not isinstance(name, str) or not name:
            raise _error(ctx, "unsupported_header", "headers", "use nonempty string header names")
        text = _text(raw_value, "headers", ctx)
        exact = _EXACT_ENV_REF.fullmatch(text)
        reference = (exact.group(1) or exact.group(2)) if exact else None
        resolved = ctx.environment.get(reference) if reference else None
        if resolved:
            ctx.add_sensitive_value(resolved)
        if reference and resolved is not None and resolved.strip():
            result[name] = {"env": reference}
        else:
            expanded = _expand_environment(text, ctx) if "$" in text else text
            if expanded.strip():
                result[name] = {
                    "env": _protect_value(
                        context,
                        name,
                        expanded,
                        ctx,
                        reference_path=("headers", name, "env"),
                    )
                }
            else:
                # V7's os.Expand turns missing references into an empty value.
                # Empty/whitespace values cannot be v8 secret references, but
                # are safe and valid as static headers.
                result[name] = expanded
                if "$" in text:
                    ctx.warning("unresolved_legacy_header_materialized_empty")
    return result


def _protect_value(
    context: str,
    field_name: str,
    value: str,
    ctx: _Context,
    *,
    reference_path: tuple[str, ...],
) -> str:
    base = "DEFENSECLAW_MIGRATED_" + re.sub(r"[^A-Za-z0-9]+", "_", f"{context}_{field_name}").upper().strip("_")
    base = base[:96]
    ctx.add_sensitive_value(value)
    digest = _sha256(value.encode("utf-8"))
    reference = EnvironmentReference(destination=context, path=reference_path)
    name = base
    suffix = 1
    while True:
        environment_value = ctx.environment.get(name)
        pending = ctx.edits.get(name)
        if pending is not None and pending.value_sha256 == digest:
            if reference not in pending.references:
                ctx.edits[name] = replace(
                    pending,
                    references=tuple(
                        sorted((*pending.references, reference), key=lambda item: (item.destination, item.path))
                    ),
                )
            return name
        # An identical ambient value is not durable provenance: it may exist
        # only in the invoking shell and disappear on restart.  Still emit a
        # set-if-absent edit so activation proves or persists the value in the
        # selected .env transaction.
        if (environment_value is None or environment_value == value) and pending is None:
            break
        suffix += 1
        stable_suffix = f"_{digest[:8]}" if suffix == 2 else f"_{digest[:8]}_{suffix}"
        name = base[: 128 - len(stable_suffix)] + stable_suffix
    ctx.edits[name] = EnvironmentEdit(
        name=name,
        value=value,
        value_sha256=digest,
        references=(reference,),
    )
    ctx.warning("protected_environment_edit_required")
    return name


def _expand_environment(value: str, ctx: _Context) -> str:
    # Mirror Go os.Expand, which accepts both $NAME and ${NAME}, consumes
    # malformed brace forms, leaves a lone dollar untouched, and substitutes
    # missing names with the empty string.
    output: list[str] = []
    start = 0
    index = 0
    while index < len(value):
        if value[index] != "$" or index + 1 >= len(value):
            index += 1
            continue
        output.append(value[start:index])
        name, width = _go_shell_name(value[index + 1 :])
        if not name and width > 0:
            pass
        elif not name:
            output.append("$")
        else:
            resolved = ctx.environment.get(name, "")
            if resolved:
                ctx.add_sensitive_value(resolved)
            output.append(resolved)
        index += width + 1
        start = index
    if not output:
        return value
    output.append(value[start:])
    return "".join(output)


def _go_shell_name(value: str) -> tuple[str, int]:
    if not value:
        return "", 0
    if value[0] == "{":
        if len(value) > 2 and value[1] in _SHELL_SPECIAL and value[2] == "}":
            return value[1], 3
        closing = value.find("}", 1)
        if closing == 1:
            return "", 2
        if closing > 1:
            return value[1:closing], closing + 1
        return "", 1
    if value[0] in _SHELL_SPECIAL:
        return value[0], 1
    width = 0
    while width < len(value) and (value[width].isascii() and (value[width].isalnum() or value[width] == "_")):
        width += 1
    return value[:width], width


def _network_safety(destination: dict[str, Any], ctx: _Context) -> None:
    endpoints = [destination.get("endpoint")]
    endpoints.extend(value.get("endpoint") for value in destination.get("signal_overrides", {}).values())
    private = False
    cgnat = False
    for endpoint in endpoints:
        if not endpoint or not isinstance(endpoint, str):
            continue
        host = _endpoint_host(endpoint, ctx, "$.observability.destinations[].endpoint")
        classification = classify_endpoint_host(host)
        if classification in {ENDPOINT_HOST_LOCALHOST, ENDPOINT_HOST_PRIVATE}:
            private = True
        elif classification == ENDPOINT_HOST_CGNAT:
            cgnat = True
    if private or cgnat:
        safety: dict[str, bool] = {}
        if private:
            safety["allow_private_networks"] = True
        if cgnat:
            safety["allow_cgnat"] = True
        destination["network_safety"] = safety
        ctx.warning(f"private_network_opt_in:{destination['name']}")


def _endpoint_host(endpoint: str, ctx: _Context, path: str) -> str:
    try:
        parsed = urlsplit(endpoint if "://" in endpoint else f"//{endpoint}")
        host = parsed.hostname
    except ValueError:
        raise _error(ctx, "invalid_endpoint", path, "use a syntactically valid collector endpoint") from None
    if not host:
        raise _error(ctx, "invalid_endpoint", path, "use a collector endpoint with a host")
    return host


def _endpoint_is_loopback(endpoint: str, ctx: _Context) -> bool:
    host = _endpoint_host(endpoint, ctx, "$.otel.endpoint")
    if classify_endpoint_host(host) == ENDPOINT_HOST_LOCALHOST:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


def _tls(value: Any, path: str, ctx: _Context) -> dict[str, Any]:
    source = _mapping(value, f"{path}.tls", ctx) if value else {}
    result: dict[str, Any] = {}
    if "insecure" in source:
        if type(source["insecure"]) is not bool:
            raise _error(ctx, "unsupported_type", f"{path}.tls.insecure", "use true or false")
        result["insecure"] = source["insecure"]
    if "insecure_skip_verify" in source:
        if type(source["insecure_skip_verify"]) is not bool:
            raise _error(ctx, "unsupported_type", f"{path}.tls.insecure_skip_verify", "use true or false")
        result["insecure_skip_verify"] = source["insecure_skip_verify"]
    if ca_cert := source.get("ca_cert"):
        result["ca_cert"] = _text(ca_cert, f"{path}.tls.ca_cert", ctx)
    return result


def _legacy_otlp_endpoint_insecure(
    endpoint: Any,
    protocol: str,
    configured_insecure: bool,
    ca_cert: Any,
) -> bool:
    if configured_insecure:
        return True
    if protocol.startswith("grpc") and isinstance(ca_cert, str) and ca_cert:
        return False
    if not isinstance(endpoint, str) or "://" not in endpoint:
        return False
    scheme = urlsplit(endpoint).scheme.lower()
    if protocol.startswith("grpc"):
        return scheme != "https"
    return scheme == "http"


def _normalize_legacy_otlp_endpoint(endpoint: Any, protocol: str, insecure: bool) -> tuple[str, str]:
    if not isinstance(endpoint, str) or not endpoint:
        return "", ""
    if "://" in endpoint:
        parsed = urlsplit(endpoint)
        scheme = "http" if insecure else "https"
        normalized = urlunsplit((scheme, parsed.netloc, "", "", ""))
        if protocol.startswith("grpc"):
            return normalized, unquote(parsed.path) if parsed.path not in {"", "/"} else ""
        path = unquote(parsed.path) if parsed.path not in {"", "/"} else ""
        return normalized, path
    if protocol.startswith("http"):
        scheme = "http" if insecure else "https"
        return f"{scheme}://{endpoint}", ""
    return endpoint, ""


def _normalize_legacy_otlp_url_path(value: str) -> str:
    return value if value.startswith("/") else f"/{value}"


def _batch(value: Any, path: str, ctx: _Context) -> dict[str, int]:
    source = _mapping(value, f"{path}.batch", ctx) if value else {}
    result: dict[str, int] = {}
    for key in ("max_queue_size", "max_export_batch_size", "scheduled_delay_ms"):
        if value := source.get(key):
            result[key] = _positive_int(value, f"{path}.batch.{key}", ctx)
    return result


def _protocol(value: Any, path: str, ctx: _Context) -> str:
    protocol = _text(value, path, ctx).strip().lower()
    if protocol == "http/json":
        ctx.warning("protocol_compatibility:http/json_to_http/protobuf")
        return "http/protobuf"
    aliases = {
        "http": "http/protobuf",
        "grpc": "grpc",
        "grpc/protobuf": "grpc/protobuf",
        "http/protobuf": "http/protobuf",
    }
    if protocol not in aliases:
        raise _error(ctx, "unsupported_protocol", path, "use grpc, grpc/protobuf, http, or http/protobuf")
    return aliases[protocol]


def _first_env(environment: Mapping[str, str], *names: str) -> str:
    for name in names:
        value = environment.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _first_nonempty_text(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _effective_otel_enabled(otel: Mapping[str, Any], ctx: _Context) -> bool:
    configured = otel.get("enabled", False)
    if type(configured) is not bool:
        raise _error(ctx, "unsupported_type", "$.otel.enabled", "use true or false")
    environment = ctx.environment.get("DEFENSECLAW_OTEL_ENABLED", "")
    if environment == "":
        return configured
    ctx.warning("environment_decision:DEFENSECLAW_OTEL_ENABLED")
    if environment in _OTEL_TRUE:
        return True
    if environment in _OTEL_FALSE:
        return False
    raise _error(
        ctx,
        "invalid_environment_boolean",
        "$environment.DEFENSECLAW_OTEL_ENABLED",
        "use the exact Go boolean vocabulary without surrounding whitespace",
    )


def _mapping(value: Any, path: str, ctx: _Context) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _error(ctx, "unsupported_type", path, "use a mapping")
    return value


def _sequence(value: Any, path: str, ctx: _Context) -> Sequence[Any]:
    if not isinstance(value, list):
        raise _error(ctx, "unsupported_type", path, "use a YAML sequence")
    return value


def _string_sequence(value: Any, path: str, ctx: _Context) -> Sequence[str]:
    sequence = _sequence(value, path, ctx)
    if any(not isinstance(item, str) or not item for item in sequence):
        raise _error(ctx, "unsupported_type", path, "use nonempty string sequence entries")
    return sequence


def _text(value: Any, path: str, ctx: _Context) -> str:
    if not isinstance(value, str) or not value:
        raise _error(ctx, "unsupported_type", path, "use a nonempty string")
    return value


def _env_name(value: Any, path: str, ctx: _Context) -> str:
    name = _text(value, path, ctx)
    if not _ENV_RE.fullmatch(name):
        raise _error(ctx, "unsupported_environment_name", path, "use a valid environment variable name")
    return name


def _positive_int(value: Any, path: str, ctx: _Context) -> int:
    if type(value) is not int or value <= 0:
        raise _error(ctx, "unsupported_type", path, "use a positive integer")
    return value


def _legacy_positive_value(value: Any) -> int | None:
    return value if type(value) is int and value > 0 else None


def _legacy_positive_or_default(value: Any, default: int, path: str, ctx: _Context) -> int:
    if value is None:
        return default
    if type(value) is not int:
        raise _error(ctx, "unsupported_type", path, "use an integer")
    return value if value > 0 else default


def _effective_otel_batch(
    source: Mapping[str, Any],
    inherited: Mapping[str, int],
    path: str,
    ctx: _Context,
) -> dict[str, int]:
    result: dict[str, int] = {}
    for key, built_in in _V7_OTEL_BATCH_DEFAULTS.items():
        fallback = inherited.get(key, built_in)
        result[key] = _legacy_positive_or_default(source.get(key), fallback, f"{path}.{key}", ctx)
    return result


def _legacy_temporality(value: Any, path: str, ctx: _Context, *, default: str = "delta") -> str:
    if value in (None, ""):
        return default
    if not isinstance(value, str):
        raise _error(ctx, "unsupported_type", path, "use text")
    # V7 treats only cumulative (case-insensitive) specially; every other
    # string selects delta rather than failing provider construction.
    return "cumulative" if value.strip().lower() == "cumulative" else "delta"


def _is_legacy_scalar(value: Any) -> bool:
    return value is None or not isinstance(value, (Mapping, list, tuple, set))


def _legacy_scalar_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        if math.isnan(value):
            return ".nan"
        if math.isinf(value):
            return ".inf" if value > 0 else "-.inf"
    return str(value)


def _effective_positive_int(source: Mapping[str, Any], key: str, default: int, path: str, ctx: _Context) -> int:
    value = source.get(key, default)
    if type(value) is not int:
        raise _error(ctx, "unsupported_type", path, "use an integer")
    return value if value > 0 else default


def _optional_bool(source: Mapping[str, Any], key: str, path: str, ctx: _Context) -> None:
    if key in source and type(source[key]) is not bool:
        raise _error(ctx, "unsupported_type", path, "use true or false")


def _optional_string(source: Mapping[str, Any], key: str, path: str, ctx: _Context) -> None:
    if key in source and not isinstance(source[key], str):
        raise _error(ctx, "unsupported_type", path, "use text")


def _optional_int(source: Mapping[str, Any], key: str, path: str, ctx: _Context) -> None:
    if key in source and type(source[key]) is not int:
        raise _error(ctx, "unsupported_type", path, "use an integer")


def _environment_true(value: str, accepted: frozenset[str]) -> bool:
    return value.strip().lower() in accepted


def _normalize_legacy_connector_name(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"open-hands", "open_hands"}:
        return "openhands"
    return normalized


def _reject_unknown(value: Mapping[str, Any], allowed: frozenset[str], path: str, ctx: _Context) -> None:
    if unknown := sorted(str(key) for key in value if key not in allowed):
        raise _error(ctx, "unsupported_v7_shape", path, f"remove or explicitly migrate unknown field {unknown[0]}")


def _error(ctx: _Context, code: str, path: str, action: str) -> V8MigrationError:
    return V8MigrationError(code, path, action, source_name=ctx.source_name)


def _unique_name(base: str, ctx: _Context) -> str:
    if base not in ctx.used_names:
        ctx.used_names.add(base)
        return base
    suffix = 2
    while True:
        candidate = _bounded_name(f"{base}-{suffix}")
        if candidate not in ctx.used_names:
            ctx.used_names.add(candidate)
            return candidate
        suffix += 1


def _normalize_destination_name(value: Any, path: str, ctx: _Context) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _error(ctx, "unsupported_destination_name", path, "use a nonempty destination name")
    normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    if not normalized:
        normalized = "destination-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    normalized = _bounded_name(normalized)
    if normalized != value:
        ctx.warning(f"destination_name_normalized:{normalized}")
    return normalized


def _bounded_name(value: str) -> str:
    if len(value) <= 64:
        return value
    digest = hashlib.sha256(value.encode()).hexdigest()[:8]
    return value[:55].rstrip("_-") + "-" + digest


def _dump_root_entry(key: str, value: Any, newline: str) -> str:
    rendered = yaml.safe_dump(
        {key: value},
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=1_000_000,
    )
    if newline != "\n":
        rendered = rendered.replace("\n", newline)
    return rendered


def _root_pairs(root: MappingNode) -> list[tuple[ScalarNode, Node]]:
    pairs: list[tuple[ScalarNode, Node]] = []
    for key, value in root.value:
        if not isinstance(key, ScalarNode):
            continue
        pairs.append((key, value))
    return pairs


def _mapping_node_pair(root: MappingNode, name: str) -> tuple[ScalarNode, Node] | None:
    return next(((key, value) for key, value in root.value if isinstance(key, ScalarNode) and key.value == name), None)


def _root_entry_span(text: str, pairs: Sequence[tuple[ScalarNode, Node]], index: int) -> tuple[int, int]:
    start = _line_start(text, pairs[index][0].start_mark.index)
    # MappingNode.end_mark points at the next key and therefore swallows any
    # comment lines that visually belong to that next section.  Bound removal
    # by the last real descendant instead, then include only its physical line.
    content_end = _last_content_end(pairs[index][1])
    newline = text.find("\n", content_end)
    end = len(text) if newline < 0 else newline + 1
    return start, end


def _line_start(text: str, index: int) -> int:
    return text.rfind("\n", 0, index) + 1


def _last_content_end(node: Node) -> int:
    if isinstance(node, MappingNode):
        descendants = [child for pair in node.value for child in pair]
    elif isinstance(node, yaml.nodes.SequenceNode):
        descendants = list(node.value)
    else:
        descendants = []
    if not descendants:
        return node.end_mark.index
    return max(_last_content_end(child) for child in descendants)


def _entry_comments(text: str, start: int, end: int, key_node: Node, value_node: Node) -> tuple[str, ...]:
    """Return comments outside all parsed scalar ranges in one root entry."""

    scalar_ranges = sorted((*_scalar_ranges(key_node), *_scalar_ranges(value_node)))
    range_index = 0
    comments: list[str] = []
    cursor = start
    for raw_line in text[start:end].splitlines(keepends=True):
        for index, character in enumerate(raw_line):
            absolute = cursor + index
            if character != "#" or (index > 0 and not raw_line[index - 1].isspace()):
                continue
            while range_index < len(scalar_ranges) and scalar_ranges[range_index][1] <= absolute:
                range_index += 1
            inside_scalar = (
                range_index < len(scalar_ranges)
                and scalar_ranges[range_index][0] <= absolute < scalar_ranges[range_index][1]
            )
            if not inside_scalar:
                comments.append(raw_line[index:].rstrip("\r\n"))
                break
        cursor += len(raw_line)
    return tuple(comments)


def _scalar_ranges(node: Node) -> tuple[tuple[int, int], ...]:
    if isinstance(node, ScalarNode):
        return ((node.start_mark.index, node.end_mark.index),)
    if isinstance(node, MappingNode):
        children = [child for pair in node.value for child in pair]
    elif isinstance(node, yaml.nodes.SequenceNode):
        children = list(node.value)
    else:
        children = []
    return tuple(item for child in children for item in _scalar_ranges(child))


def _render_preserved_comments(comments: Sequence[str], ctx: _Context, newline: str) -> str:
    return "".join(ctx.scrub_comment(comment) + newline for comment in comments)


def _scrub_all_comment_secrets(text: str, ctx: _Context) -> str:
    if not ctx.sensitive_values:
        return text
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except (yaml.YAMLError, RecursionError, OverflowError):
        raise _error(ctx, "unsafe_source_rewrite", "$", "simplify YAML comments before upgrading") from None
    if root is None:
        return text
    scalar_ranges = sorted(_scalar_ranges(root))
    range_index = 0
    edits: list[tuple[int, int, str]] = []
    cursor = 0
    for raw_line in text.splitlines(keepends=True):
        for index, character in enumerate(raw_line):
            absolute = cursor + index
            if character != "#" or (index > 0 and not raw_line[index - 1].isspace()):
                continue
            while range_index < len(scalar_ranges) and scalar_ranges[range_index][1] <= absolute:
                range_index += 1
            inside_scalar = (
                range_index < len(scalar_ranges)
                and scalar_ranges[range_index][0] <= absolute < scalar_ranges[range_index][1]
            )
            if not inside_scalar:
                comment_end = cursor + len(raw_line.rstrip("\r\n"))
                comment = text[absolute:comment_end]
                safe = ctx.scrub_comment(comment)
                if safe != comment:
                    edits.append((absolute, comment_end, safe))
                break
        cursor += len(raw_line)
    for start, end, replacement in reversed(edits):
        text = text[:start] + replacement + text[end:]
    return text


def _reject_overlapping_edits(edits: Sequence[tuple[int, int, str]], ctx: _Context) -> None:
    spans = sorted((start, end) for start, end, _ in edits if start != end)
    for (_, left_end), (right_start, _) in zip(spans, spans[1:]):
        if right_start < left_end:
            raise _error(ctx, "unsafe_source_rewrite", "$", "normalize the modified YAML sections before upgrading")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
