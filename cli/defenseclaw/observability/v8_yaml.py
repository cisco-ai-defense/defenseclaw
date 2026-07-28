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

"""Comment-preserving, surgical mutations for v8 observability YAML.

PyYAML is deliberately used only as a strict parser and span locator.  It is
not a round-trip serializer: re-emitting an operator's whole ``config.yaml``
would discard comments, ASCII diagrams, scalar quoting, and formatting.  This
module instead replaces only the source span named by an allow-listed path and
returns bytes suitable for a caller-owned, locked atomic replacement.

The public API performs no file or environment I/O and never includes source or
replacement values in diagnostics or object representations.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, TypeAlias

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from defenseclaw.observability.v8_config import V8ConfigError, _preflight_yaml_structure

PathPart: TypeAlias = str | int
YAMLPath: TypeAlias = tuple[PathPart, ...]

_MAX_SOURCE_BYTES: Final = 4_194_304
_MAX_NODES: Final = 65_536
_MAX_DEPTH: Final = 32
_MAX_MAPPING_ENTRIES: Final = 1_024
_MAX_DESTINATIONS: Final = 64
_MAX_ROUTES_PER_DESTINATION: Final = 256
_MAX_ROUTES_TOTAL: Final = 4_096
_MAX_PROFILES: Final = 128

_STABLE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_BUCKETS: Final = frozenset(
    {
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
    }
)
_SIGNALS: Final = frozenset({"logs", "traces", "metrics"})
_FIELD_CLASSES: Final = frozenset(
    {"metadata", "identifier", "content", "reason", "evidence", "error", "path", "credential"}
)
_TRACE_LIMITS: Final = frozenset(
    {
        "max_attributes_per_span",
        "max_events_per_span",
        "max_links_per_span",
        "max_attributes_per_event",
        "max_attribute_value_bytes",
        "max_projected_span_bytes",
        "max_stacktrace_bytes",
        "max_message_items",
    }
)
_DESTINATION_SCALARS: Final = frozenset(
    {
        "name",
        "kind",
        "enabled",
        "preset",
        "path",
        "listen",
        "endpoint",
        "protocol",
        "method",
        "token_env",
        "bearer_env",
        "index",
        "source",
        "sourcetype",
        "timeout_ms",
    }
)
_DESTINATION_NESTED: Final = {
    "rotation": frozenset({"max_size_mb", "max_backups", "max_age_days", "compress"}),
    "tls": frozenset({"insecure", "insecure_skip_verify", "ca_cert"}),
    "batch": frozenset(
        {
            "max_queue_size",
            "max_queue_bytes",
            "max_export_batch_size",
            "max_export_batch_bytes",
            "scheduled_delay_ms",
        }
    ),
    "network_safety": frozenset({"allow_private_networks", "allow_cgnat"}),
}
_MISSING: Final = object()


class V8YAMLMutationError(ValueError):
    """A value-safe v8 YAML parse, safety, path, or mutation error."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        source: str,
        path: YAMLPath = (),
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        self.code = code
        self.source = source
        self.path = path
        self.line = line
        self.column = column
        location = source
        if line is not None:
            location += f":{line}"
            if column is not None:
                location += f":{column}"
        if path:
            location += f" ({_display_path(path)})"
        super().__init__(f"{location}: {message} [{code}]")


class _DeleteValue:
    __slots__ = ()

    def __repr__(self) -> str:
        return "DELETE"


DELETE: Final = _DeleteValue()


@dataclass(frozen=True)
class V8YAMLMutation:
    """One exact allow-listed source mutation.

    ``path`` is a tuple, not a dotted string, because bucket IDs and resource
    attribute names legitimately contain dots.  Use :meth:`delete` to remove an
    optional mapping entry or sequence item.
    """

    path: YAMLPath
    value: Any = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", tuple(self.path))

    @classmethod
    def set(cls, path: Sequence[PathPart], value: Any) -> V8YAMLMutation:
        return cls(tuple(path), value)

    @classmethod
    def delete(cls, path: Sequence[PathPart]) -> V8YAMLMutation:
        return cls(tuple(path), DELETE)


@dataclass(frozen=True)
class PreparedV8YAMLWrite:
    """Deterministic bytes and compare-before-replace metadata.

    The candidate is excluded from ``repr`` so an accidental diagnostic cannot
    print credentials or content embedded elsewhere in ``config.yaml``.
    """

    candidate: bytes = field(repr=False)
    expected_sha256: str
    candidate_sha256: str
    changed: bool
    newline: str


@dataclass(frozen=True)
class _ParsedYAML:
    root: Node
    value: Any = field(repr=False)


class _StrictSafeLoader(yaml.SafeLoader):
    def compose_node(self, parent: Node | None, index: int | None) -> Node:
        if self.check_event(AliasEvent):
            event = self.peek_event()
            mark = event.start_mark
            raise V8YAMLMutationError(
                "yaml_alias_forbidden",
                "YAML aliases are not allowed in v8 configuration",
                source=getattr(self, "_v8_source_name", "config.yaml"),
                line=mark.line + 1,
                column=mark.column + 1,
            )
        return super().compose_node(parent, index)


class _NoAliasIndentedDumper(yaml.SafeDumper):
    def ignore_aliases(self, data: Any) -> bool:
        return True

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        return super().increase_indent(flow, False)


def prepare_v8_yaml_write(
    source: bytes | str,
    mutations: Iterable[V8YAMLMutation],
    *,
    source_name: str = "config.yaml",
) -> PreparedV8YAMLWrite:
    """Validate and prepare a comment-preserving v8 YAML candidate.

    No file is opened or replaced.  Callers should hold their normal config
    lock, compare the current file digest with ``expected_sha256``, preserve
    permissions, write ``candidate`` to a sibling temporary file, validate it,
    and atomically replace the original.
    """

    original = _source_bytes(source, source_name)
    text = _decode_source(original, source_name)
    parsed = _parse_v8(text, source_name)
    newline = _detect_newline(text)

    candidate = text
    for mutation in mutations:
        path = tuple(mutation.path)
        if not _supported_path(path):
            raise V8YAMLMutationError(
                "unsupported_mutation_path",
                "the requested path is not an exact supported v8 observability mutation",
                source=source_name,
                path=path,
            )
        if mutation.value is not DELETE:
            _validate_replacement_value(mutation.value, source_name, path)
        candidate = _apply_mutation(candidate, parsed, mutation, source_name, newline)
        if len(candidate.encode("utf-8")) > _MAX_SOURCE_BYTES:
            raise V8YAMLMutationError(
                "source_too_large",
                "v8 configuration exceeds the 4 MiB source limit after mutation",
                source=source_name,
                path=path,
            )
        parsed = _parse_v8(candidate, source_name)

    encoded = candidate.encode("utf-8")
    return PreparedV8YAMLWrite(
        candidate=encoded,
        expected_sha256=hashlib.sha256(original).hexdigest(),
        candidate_sha256=hashlib.sha256(encoded).hexdigest(),
        changed=encoded != original,
        newline=newline,
    )


def _source_bytes(source: bytes | str, source_name: str) -> bytes:
    if isinstance(source, bytes):
        raw = source
    elif isinstance(source, str):
        raw = source.encode("utf-8")
    else:
        raise V8YAMLMutationError(
            "invalid_source_type",
            "source must be UTF-8 text or bytes",
            source=source_name,
        )
    if len(raw) > _MAX_SOURCE_BYTES:
        raise V8YAMLMutationError(
            "source_too_large",
            "v8 configuration exceeds the 4 MiB source limit",
            source=source_name,
        )
    return raw


def _decode_source(raw: bytes, source_name: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise V8YAMLMutationError(
            "invalid_utf8",
            "v8 configuration must be valid UTF-8",
            source=source_name,
            line=error.start + 1,
        ) from None


def _parse_v8(text: str, source_name: str) -> _ParsedYAML:
    try:
        # PyYAML composes nested flow collections recursively. Enforce the
        # shared limits from its streaming event surface before allocating the
        # syntax tree used for surgical source spans.
        _preflight_yaml_structure(text, source_name, reject_aliases=False)
    except V8ConfigError as error:
        code = "source_too_complex" if error.keyword.startswith("max-") else "invalid_yaml"
        message = (
            "configuration exceeds safe YAML limits"
            if code == "source_too_complex"
            else "configuration is not valid safe YAML"
        )
        raise V8YAMLMutationError(
            code,
            message,
            source=source_name,
        ) from None
    loader = _StrictSafeLoader(text)
    loader._v8_source_name = source_name  # type: ignore[attr-defined]
    try:
        root = loader.get_single_node()
        if root is None:
            raise V8YAMLMutationError(
                "empty_document",
                "v8 configuration must contain one mapping document",
                source=source_name,
            )
        _validate_syntax_tree(root, source_name)
        value = loader.construct_document(root)
    except V8YAMLMutationError:
        raise
    except (RecursionError, OverflowError):
        raise V8YAMLMutationError(
            "source_too_complex",
            "configuration exceeds safe YAML limits",
            source=source_name,
        ) from None
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None) or getattr(error, "context_mark", None)
        raise V8YAMLMutationError(
            "invalid_yaml",
            "configuration is not valid safe YAML",
            source=source_name,
            line=mark.line + 1 if mark is not None else None,
            column=mark.column + 1 if mark is not None else None,
        ) from None
    finally:
        loader.dispose()

    if not isinstance(root, MappingNode) or not isinstance(value, dict):
        raise V8YAMLMutationError(
            "invalid_root",
            "v8 configuration root must be a mapping",
            source=source_name,
            line=root.start_mark.line + 1,
            column=root.start_mark.column + 1,
        )
    version = value.get("config_version", _MISSING)
    if type(version) is not int or version != 8:
        raise V8YAMLMutationError(
            "not_v8_configuration",
            "comment-preserving observability mutations require config_version 8",
            source=source_name,
            path=("config_version",),
        )
    _validate_effective_source_counts(value, source_name)
    return _ParsedYAML(root=root, value=value)


def _validate_syntax_tree(root: Node, source_name: str) -> None:
    count = 0

    def visit(node: Node, depth: int, path: YAMLPath) -> None:
        nonlocal count
        count += 1
        if count > _MAX_NODES:
            raise _node_error("too_many_nodes", "v8 configuration exceeds the YAML node limit", source_name, node, path)
        is_container = isinstance(node, (MappingNode, SequenceNode))
        if is_container and depth > _MAX_DEPTH:
            raise _node_error("yaml_too_deep", "v8 configuration exceeds the YAML depth limit", source_name, node, path)
        if isinstance(node, MappingNode):
            if len(node.value) > _MAX_MAPPING_ENTRIES:
                raise _node_error(
                    "mapping_too_large",
                    "a YAML mapping exceeds the v8 entry limit",
                    source_name,
                    node,
                    path,
                )
            seen: set[str] = set()
            for key, value in node.value:
                if isinstance(key, ScalarNode) and (key.value == "<<" or key.tag == "tag:yaml.org,2002:merge"):
                    raise _node_error(
                        "yaml_merge_forbidden",
                        "YAML merge keys are not allowed in v8 configuration",
                        source_name,
                        key,
                        path + ("<<",),
                    )
                if not isinstance(key, ScalarNode) or key.tag != "tag:yaml.org,2002:str":
                    raise _node_error(
                        "non_string_mapping_key",
                        "v8 mapping keys must be strings",
                        source_name,
                        key,
                        path,
                    )
                child_path = path + (key.value,)
                if key.value in seen:
                    raise _node_error(
                        "duplicate_mapping_key",
                        "duplicate YAML mapping keys are not allowed in v8 configuration",
                        source_name,
                        key,
                        child_path,
                    )
                seen.add(key.value)
                visit(key, depth, child_path)
                child_depth = depth + int(isinstance(value, (MappingNode, SequenceNode)))
                visit(value, child_depth, child_path)
        elif isinstance(node, SequenceNode):
            for index, child in enumerate(node.value):
                child_depth = depth + int(isinstance(child, (MappingNode, SequenceNode)))
                visit(child, child_depth, path + (index,))

    visit(root, 1, ())


def _validate_effective_source_counts(value: dict[str, Any], source_name: str) -> None:
    observability = value.get("observability")
    if observability is None:
        return
    if not isinstance(observability, dict):
        return  # Canonical schema validation owns value-type diagnostics.
    destinations = observability.get("destinations", [])
    if isinstance(destinations, list):
        if len(destinations) > _MAX_DESTINATIONS:
            raise V8YAMLMutationError(
                "too_many_destinations",
                "observability exceeds the destination limit",
                source=source_name,
                path=("observability", "destinations"),
            )
        total_routes = 0
        for index, destination in enumerate(destinations):
            if not isinstance(destination, dict):
                continue
            routes = destination.get("routes", [])
            if isinstance(routes, list):
                if len(routes) > _MAX_ROUTES_PER_DESTINATION:
                    raise V8YAMLMutationError(
                        "too_many_destination_routes",
                        "a destination exceeds the explicit route limit",
                        source=source_name,
                        path=("observability", "destinations", index, "routes"),
                    )
                total_routes += len(routes)
        if total_routes > _MAX_ROUTES_TOTAL:
            raise V8YAMLMutationError(
                "too_many_routes",
                "observability exceeds the total explicit route limit",
                source=source_name,
                path=("observability", "destinations"),
            )
    profiles = observability.get("redaction_profiles", {})
    if isinstance(profiles, dict) and len(profiles) > _MAX_PROFILES:
        raise V8YAMLMutationError(
            "too_many_redaction_profiles",
            "observability exceeds the custom redaction-profile limit",
            source=source_name,
            path=("observability", "redaction_profiles"),
        )


def _node_error(
    code: str,
    message: str,
    source: str,
    node: Node,
    path: YAMLPath,
) -> V8YAMLMutationError:
    return V8YAMLMutationError(
        code,
        message,
        source=source,
        path=path,
        line=node.start_mark.line + 1,
        column=node.start_mark.column + 1,
    )


def _validate_replacement_value(value: Any, source: str, path: YAMLPath) -> None:
    active: set[int] = set()
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_NODES or depth > _MAX_DEPTH:
            raise V8YAMLMutationError(
                "replacement_too_complex",
                "replacement exceeds v8 structural limits",
                source=source,
                path=path,
            )
        if item is None or type(item) in {bool, int, str}:
            return
        if isinstance(item, (list, tuple)):
            identity = id(item)
            if identity in active:
                raise V8YAMLMutationError(
                    "cyclic_replacement",
                    "replacement values must not contain cycles",
                    source=source,
                    path=path,
                )
            active.add(identity)
            for child in item:
                visit(child, depth + 1)
            active.remove(identity)
            return
        if isinstance(item, dict):
            if len(item) > _MAX_MAPPING_ENTRIES or any(type(key) is not str for key in item):
                raise V8YAMLMutationError(
                    "invalid_replacement_mapping",
                    "replacement mappings require bounded string keys",
                    source=source,
                    path=path,
                )
            identity = id(item)
            if identity in active:
                raise V8YAMLMutationError(
                    "cyclic_replacement",
                    "replacement values must not contain cycles",
                    source=source,
                    path=path,
                )
            active.add(identity)
            for child in item.values():
                visit(child, depth + 1)
            active.remove(identity)
            return
        raise V8YAMLMutationError(
            "invalid_replacement_type",
            "replacement contains a value type unsupported by v8 YAML",
            source=source,
            path=path,
        )

    visit(value, 1)


def _apply_mutation(
    text: str,
    parsed: _ParsedYAML,
    mutation: V8YAMLMutation,
    source_name: str,
    newline: str,
) -> str:
    path = tuple(mutation.path)
    located = _locate(parsed.root, parsed.value, path)
    if located is not None:
        node, current, parent_node, parent_value, parent_part = located
        if mutation.value is DELETE:
            if parent_node is None:
                raise V8YAMLMutationError(
                    "root_mutation_forbidden",
                    "the configuration root cannot be deleted",
                    source=source_name,
                    path=path,
                )
            return _delete_existing(text, parent_node, parent_part, node)
        if _same_value(current, mutation.value):
            return text
        rendered = _render_replacement(mutation.value, node, newline, source_name, path)
        end = node.end_mark.index
        if isinstance(node, (MappingNode, SequenceNode)) and not node.flow_style:
            end = _block_content_end(text, node)
            if text[node.start_mark.index : end].endswith(("\n", "\r")):
                rendered += newline
        return text[: node.start_mark.index] + rendered + text[end:]

    if mutation.value is DELETE:
        return text
    return _insert_missing(text, parsed.root, parsed.value, path, mutation.value, newline, source_name)


def _locate(
    root: Node,
    value: Any,
    path: YAMLPath,
) -> tuple[Node, Any, Node | None, Any, PathPart | None] | None:
    node = root
    current = value
    parent_node: Node | None = None
    parent_value: Any = None
    parent_part: PathPart | None = None
    for part in path:
        parent_node, parent_value, parent_part = node, current, part
        if isinstance(part, str) and isinstance(node, MappingNode) and isinstance(current, dict):
            found = _mapping_pair(node, part)
            if found is None or part not in current:
                return None
            _, node = found
            current = current[part]
        elif isinstance(part, int) and isinstance(node, SequenceNode) and isinstance(current, list):
            if part < 0 or part >= len(node.value):
                return None
            node = node.value[part]
            current = current[part]
        else:
            return None
    return node, current, parent_node, parent_value, parent_part


def _insert_missing(
    text: str,
    root: Node,
    value: Any,
    path: YAMLPath,
    replacement: Any,
    newline: str,
    source_name: str,
) -> str:
    node = root
    current = value
    for offset, part in enumerate(path):
        remainder = path[offset + 1 :]
        if isinstance(part, str) and isinstance(node, MappingNode) and isinstance(current, dict):
            found = _mapping_pair(node, part)
            if found is None or part not in current:
                nested = _build_missing_value(remainder, replacement, source_name, path)
                return _insert_mapping_entry(text, node, part, nested, newline, source_name, path)
            _, node = found
            current = current[part]
            continue
        if isinstance(part, int) and isinstance(node, SequenceNode) and isinstance(current, list):
            if part == len(node.value):
                nested = _build_missing_value(remainder, replacement, source_name, path)
                return _append_sequence_item(text, node, nested, newline, source_name, path)
            if 0 <= part < len(node.value):
                node = node.value[part]
                current = current[part]
                continue
        raise V8YAMLMutationError(
            "unreachable_mutation_path",
            "the requested path cannot be inserted through the existing YAML shape",
            source=source_name,
            path=path,
            line=node.start_mark.line + 1,
            column=node.start_mark.column + 1,
        )
    raise AssertionError("missing path insertion unexpectedly resolved")


def _build_missing_value(
    remainder: YAMLPath,
    replacement: Any,
    source_name: str,
    path: YAMLPath,
) -> Any:
    nested = replacement
    for part in reversed(remainder):
        if isinstance(part, str):
            nested = {part: nested}
        elif part == 0:
            nested = [nested]
        else:
            raise V8YAMLMutationError(
                "non_contiguous_sequence_insert",
                "new YAML sequences must be inserted starting at index zero",
                source=source_name,
                path=path,
            )
    return nested


def _insert_mapping_entry(
    text: str,
    parent: MappingNode,
    key: str,
    value: Any,
    newline: str,
    source_name: str,
    path: YAMLPath,
) -> str:
    if parent.flow_style:
        fragment = _dump_flow_mapping_entry(key, value, source_name, path)
        close = _closing_delimiter(text, parent, "}", source_name, path)
        prefix = _flow_insertion_prefix(text, parent, close)
        return text[:close] + prefix + fragment + text[close:]

    indent = parent.value[0][0].start_mark.column if parent.value else parent.start_mark.column
    fragment = _dump_block({key: value}, newline, source_name, path)
    fragment = _prefix_lines(fragment, " " * indent, newline)
    at = _block_content_end(text, parent)
    lead = "" if at == 0 or text[at - 1] in "\r\n" else newline
    return text[:at] + lead + fragment + text[at:]


def _append_sequence_item(
    text: str,
    parent: SequenceNode,
    value: Any,
    newline: str,
    source_name: str,
    path: YAMLPath,
) -> str:
    if parent.flow_style:
        fragment = _dump_flow(value, source_name, path)
        close = _closing_delimiter(text, parent, "]", source_name, path)
        prefix = _flow_insertion_prefix(text, parent, close)
        return text[:close] + prefix + fragment + text[close:]

    indent = parent.start_mark.column
    fragment = _dump_block([value], newline, source_name, path)
    fragment = _prefix_lines(fragment, " " * indent, newline)
    at = _block_content_end(text, parent)
    lead = "" if at == 0 or text[at - 1] in "\r\n" else newline
    return text[:at] + lead + fragment + text[at:]


def _delete_existing(text: str, parent: Node, part: PathPart | None, node: Node) -> str:
    if isinstance(parent, MappingNode) and isinstance(part, str):
        pair = _mapping_pair(parent, part)
        if pair is None:
            return text
        key, value = pair
        if parent.flow_style:
            return _delete_flow_element(text, parent, key.start_mark.index, value.end_mark.index, pair)
        if len(parent.value) == 1:
            end = _block_content_end(text, parent)
            replacement = "{}" + (
                _detect_newline(text) if text[parent.start_mark.index : end].endswith(("\n", "\r")) else ""
            )
            return text[: parent.start_mark.index] + replacement + text[end:]
        start = _line_start(text, key.start_mark.index)
        end = _block_content_end(text, value)
        return text[:start] + text[end:]
    if isinstance(parent, SequenceNode) and isinstance(part, int):
        if parent.flow_style:
            return _delete_flow_element(text, parent, node.start_mark.index, node.end_mark.index, node)
        if len(parent.value) == 1:
            end = _block_content_end(text, parent)
            replacement = "[]" + (
                _detect_newline(text) if text[parent.start_mark.index : end].endswith(("\n", "\r")) else ""
            )
            return text[: parent.start_mark.index] + replacement + text[end:]
        start = _line_start(text, node.start_mark.index)
        end = _block_content_end(text, node)
        return text[:start] + text[end:]
    return text


def _delete_flow_element(
    text: str,
    parent: MappingNode | SequenceNode,
    start: int,
    end: int,
    identity: Any,
) -> str:
    items = parent.value
    index = items.index(identity)
    if len(items) == 1:
        return text[:start] + text[end:]
    if index > 0:
        previous = items[index - 1]
        if isinstance(parent, MappingNode):
            previous_end = previous[1].end_mark.index
        else:
            previous_end = previous.end_mark.index
        separator = text[previous_end:start]
        # A comment terminates at the newline inside the separator. Preserve
        # that newline (and a legal trailing comma) so the closing flow
        # delimiter cannot be swallowed by the comment after deletion.
        if "#" in separator:
            return text[:start] + text[end:]
        cursor = start
        while cursor > parent.start_mark.index and text[cursor - 1].isspace():
            cursor -= 1
        if cursor > parent.start_mark.index and text[cursor - 1] == ",":
            cursor -= 1
        return text[:cursor] + text[end:]
    cursor = end
    while cursor < parent.end_mark.index and text[cursor].isspace():
        cursor += 1
    if cursor < parent.end_mark.index and text[cursor] == ",":
        cursor += 1
        while cursor < parent.end_mark.index and text[cursor].isspace():
            cursor += 1
    return text[:start] + text[cursor:]


def _flow_insertion_prefix(
    text: str,
    parent: MappingNode | SequenceNode,
    close: int,
) -> str:
    if not parent.value:
        return ""
    if isinstance(parent, MappingNode):
        last_end = parent.value[-1][1].end_mark.index
    else:
        last_end = parent.value[-1].end_mark.index
    suffix = text[last_end:close]
    in_comment = False
    for character in suffix:
        if in_comment:
            if character in "\r\n":
                in_comment = False
            continue
        if character == "#":
            in_comment = True
        elif character == ",":
            # Preserve an existing legal trailing comma instead of emitting a
            # second separator immediately before the inserted flow element.
            return " "
    return ", "


def _render_replacement(
    value: Any,
    existing: Node,
    newline: str,
    source_name: str,
    path: YAMLPath,
) -> str:
    if isinstance(existing, ScalarNode) and isinstance(value, str):
        if existing.style == '"':
            return _double_quoted(value)
        if existing.style == "'" and all(character >= " " for character in value):
            return "'" + value.replace("'", "''") + "'"
        if "\n" in value or "\r" in value or any(character < " " for character in value):
            return _double_quoted(value)
    if getattr(existing, "flow_style", False):
        return _dump_flow(value, source_name, path)
    if isinstance(existing, ScalarNode):
        return _dump_flow(value, source_name, path)
    rendered = _dump_block(value, newline, source_name, path).rstrip("\r\n")
    return _prefix_continuation_lines(rendered, " " * existing.start_mark.column, newline)


def _dump_flow(value: Any, source_name: str, path: YAMLPath) -> str:
    try:
        rendered = yaml.dump(
            value,
            Dumper=_NoAliasIndentedDumper,
            allow_unicode=True,
            default_flow_style=True,
            sort_keys=False,
            width=4_096,
        )
    except yaml.YAMLError:
        raise V8YAMLMutationError(
            "replacement_render_failed",
            "replacement could not be rendered safely",
            source=source_name,
            path=path,
        ) from None
    return _strip_yaml_document_end(rendered).strip()


def _dump_flow_mapping_entry(key: str, value: Any, source_name: str, path: YAMLPath) -> str:
    rendered = _dump_flow({key: value}, source_name, path)
    if not (rendered.startswith("{") and rendered.endswith("}")):
        raise V8YAMLMutationError(
            "replacement_render_failed",
            "replacement mapping could not be rendered safely",
            source=source_name,
            path=path,
        )
    return rendered[1:-1]


def _dump_block(value: Any, newline: str, source_name: str, path: YAMLPath) -> str:
    try:
        rendered = yaml.dump(
            value,
            Dumper=_NoAliasIndentedDumper,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
            width=4_096,
            indent=2,
        )
    except yaml.YAMLError:
        raise V8YAMLMutationError(
            "replacement_render_failed",
            "replacement could not be rendered safely",
            source=source_name,
            path=path,
        ) from None
    rendered = _strip_yaml_document_end(rendered)
    if not rendered.endswith("\n"):
        rendered += "\n"
    return rendered.replace("\n", newline)


def _strip_yaml_document_end(rendered: str) -> str:
    if rendered.endswith("...\n"):
        rendered = rendered[:-4]
    return rendered


def _double_quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _prefix_lines(text: str, prefix: str, newline: str) -> str:
    trailing = text.endswith(newline)
    lines = text[: -len(newline)].split(newline) if trailing else text.split(newline)
    rendered = newline.join(prefix + line if line else line for line in lines)
    return rendered + (newline if trailing else "")


def _prefix_continuation_lines(text: str, prefix: str, newline: str) -> str:
    lines = text.split(newline)
    if len(lines) < 2:
        return text
    return newline.join([lines[0], *(prefix + line if line else line for line in lines[1:])])


def _mapping_pair(node: MappingNode, key: str) -> tuple[Node, Node] | None:
    for candidate, value in node.value:
        if isinstance(candidate, ScalarNode) and candidate.value == key:
            return candidate, value
    return None


def _same_value(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return list(left.keys()) == list(right.keys()) and all(_same_value(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_same_value(a, b) for a, b in zip(left, right, strict=True))
    return bool(left == right)


def _detect_newline(text: str) -> str:
    first = text.find("\n")
    if first > 0 and text[first - 1] == "\r":
        return "\r\n"
    return "\n"


def _line_start(text: str, index: int) -> int:
    return text.rfind("\n", 0, index) + 1


def _line_end(text: str, index: int) -> int:
    newline = text.find("\n", index)
    return len(text) if newline < 0 else newline + 1


def _block_content_end(text: str, node: Node) -> int:
    """End after the node's final content line, before trailing comments."""

    current = node
    while True:
        if isinstance(current, MappingNode) and current.value:
            current = current.value[-1][1]
            continue
        if isinstance(current, SequenceNode) and current.value:
            current = current.value[-1]
            continue
        break
    return _line_end(text, current.end_mark.index)


def _closing_delimiter(
    text: str,
    node: Node,
    delimiter: str,
    source_name: str,
    path: YAMLPath,
) -> int:
    cursor = node.end_mark.index - 1
    while cursor >= node.start_mark.index and text[cursor].isspace():
        cursor -= 1
    if cursor < node.start_mark.index or text[cursor] != delimiter:
        raise V8YAMLMutationError(
            "unsafe_source_span",
            "the requested flow-style source span could not be patched safely",
            source=source_name,
            path=path,
        )
    return cursor


def _display_path(path: YAMLPath) -> str:
    result = "$"
    for part in path:
        if isinstance(part, int):
            result += f"[{part}]"
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", part):
            result += "." + part
        else:
            result += "[" + _double_quoted(part) + "]"
    return result


def _supported_path(path: YAMLPath) -> bool:
    if len(path) < 2 or path[0] != "observability" or not all(type(part) in {str, int} for part in path):
        return False
    section = path[1]
    if section == "bucket_catalog_version":
        return len(path) == 2
    if section == "resource":
        return len(path) == 4 and path[2] == "attributes" and isinstance(path[3], str) and bool(path[3])
    if section == "trace_policy":
        if len(path) == 3:
            return path[2] in {"sampler", "sampler_arg", "semantic_profile", "compatibility_aliases"}
        return len(path) == 4 and path[2] == "limits" and path[3] in _TRACE_LIMITS
    if section == "metric_policy":
        return len(path) == 3 and path[2] in {"export_interval_seconds", "temporality"}
    if section == "defaults":
        return (len(path) == 3 and path[2] == "redaction_profile") or (
            len(path) == 4 and path[2] == "collect" and path[3] in _SIGNALS
        )
    if section == "buckets":
        return _supported_bucket_path(path)
    if section == "redaction_profiles":
        return _supported_profile_path(path)
    if section == "local":
        return len(path) == 3 and path[2] in {"path", "judge_bodies_path", "retention_days"}
    if section == "connectors":
        return (
            len(path) == 4
            and isinstance(path[2], str)
            and bool(_STABLE_NAME.fullmatch(path[2]))
            and path[3] == "webhooks"
        )
    if section == "destinations":
        return _supported_destination_path(path)
    return False


def _supported_bucket_path(path: YAMLPath) -> bool:
    if len(path) < 3 or path[2] not in _BUCKETS:
        return False
    if len(path) == 3:
        return True
    if len(path) == 4:
        return path[3] == "redaction_profile"
    return len(path) == 5 and path[3] == "collect" and path[4] in _SIGNALS


def _supported_profile_path(path: YAMLPath) -> bool:
    if len(path) < 3 or not isinstance(path[2], str) or not _STABLE_NAME.fullmatch(path[2]):
        return False
    if len(path) == 3:
        return True
    if len(path) == 4:
        return path[3] in {"extends", "detectors"}
    return len(path) == 5 and path[3] == "field_classes" and path[4] in _FIELD_CLASSES


def _supported_destination_path(path: YAMLPath) -> bool:
    if len(path) < 3 or not isinstance(path[2], int) or path[2] < 0:
        return False
    if len(path) == 3:
        return True
    field_name = path[3]
    if len(path) == 4:
        return field_name in _DESTINATION_SCALARS or field_name == "send"
    if len(path) == 5 and field_name in _DESTINATION_NESTED:
        return path[4] in _DESTINATION_NESTED[field_name]
    if len(path) == 5 and field_name == "headers":
        return isinstance(path[4], str) and bool(path[4])
    if len(path) == 5 and field_name == "signal_overrides":
        return path[4] in _SIGNALS
    if len(path) == 6 and field_name == "signal_overrides":
        return path[4] in _SIGNALS and path[5] in {"endpoint", "path"}
    if field_name == "send":
        return len(path) == 5 and path[4] in {"signals", "buckets", "redaction_profile"}
    if field_name != "routes" or len(path) < 5 or not isinstance(path[4], int) or path[4] < 0:
        return False
    if len(path) == 5:
        return True
    if len(path) == 6:
        return path[5] in {"name", "signals", "action", "redaction_profile"}
    return (
        len(path) == 7
        and path[5] == "selector"
        and path[6]
        in {
            "buckets",
            "sources",
            "connectors",
            "actions",
            "event_names",
            "min_severity",
        }
    )


__all__ = [
    "DELETE",
    "PreparedV8YAMLWrite",
    "V8YAMLMutation",
    "V8YAMLMutationError",
    "prepare_v8_yaml_write",
]
