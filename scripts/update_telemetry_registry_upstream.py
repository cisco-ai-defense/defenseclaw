#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Explicitly refresh pinned normalized telemetry semantic-convention snapshots.

This is the only telemetry-registry command that performs network access. It
downloads immutable archives from the primary upstream repositories and derives
reviewable normalized snapshots. Normal registry compilation never imports or
invokes this module.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import fcntl
import hashlib
import io
import json
import os
import re
import secrets
import stat
import sys
import tarfile
import threading
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any, Final

import yaml
from generate_telemetry_registry import (
    EXPECTED_DEPENDENCIES,
    NORMALIZED_SNAPSHOT_FORMAT,
    REQUIRED_OPENINFERENCE_ATTRIBUTES,
    RegistryError,
    _parse_yaml_strict_bytes,
    load_yaml_strict,
)

MAX_ARCHIVE_BYTES: Final = 128 * 1024 * 1024
MAX_SOURCE_FILE_BYTES: Final = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS: Final = 100_000
MAX_EXPANDED_BYTES: Final = 512 * 1024 * 1024
MAX_AUTHORED_JSON_NESTING: Final = 256
MAX_LOCK_BYTES: Final = 16 * 1024 * 1024
LEGACY_NORMALIZED_SNAPSHOT_FORMAT: Final = "defenseclaw-normalized-semconv-v1"
_PROCESS_UPDATE_LOCK: Final = threading.Lock()
ALLOWED_REPOSITORIES: Final = {
    "otel_core": "https://github.com/open-telemetry/semantic-conventions",
    "otel_genai": "https://github.com/open-telemetry/semantic-conventions-genai",
    "openinference": "https://github.com/Arize-ai/openinference",
}
EXPECTED_PROFILE_IDS: Final = {
    "otel_core": "otel-semconv-v1.42.0",
    "otel_genai": "otel-genai-b028dceecdad117461a785c3af35315e7184e813",
    "openinference": "openinference-semantic-conventions-v0.1.30",
}
OTEL_GENAI_STRUCTURAL_INPUTS: Final = (
    (
        "model/gen-ai/gen-ai-input-messages.json",
        "034fcd8c87f1e013f3a5a5018503210e2bee4d2499c361823b96e906d40a50ad",
    ),
    (
        "model/gen-ai/gen-ai-output-messages.json",
        "a825a6c0cc1b7b22fdbfb9488d8dc3a318be3897ef6d3dbae01a10297bb6e569",
    ),
    (
        "model/gen-ai/gen-ai-tool-call-arguments.json",
        "73607a8e8d9e84393475ef460108c59dbb9e1d2ddc0d0177fce6f735a62367ea",
    ),
    (
        "model/gen-ai/gen-ai-tool-call-result.json",
        "44eb4a93b05eea7da14489f1d253814c6429772d1fe869f8f6fc1749d7593412",
    ),
)
OPENINFERENCE_SEMCONV_FILES: Final = frozenset(
    {
        "python/openinference-semantic-conventions/src/openinference/semconv/resource/__init__.py",
        "python/openinference-semantic-conventions/src/openinference/semconv/trace/__init__.py",
        "python/openinference-semantic-conventions/src/openinference/semconv/version.py",
        "spec/semantic_conventions.md",
    }
)
OPENINFERENCE_PYTHON_FILES: Final = frozenset(
    {
        "python/openinference-semantic-conventions/src/openinference/semconv/resource/__init__.py",
        "python/openinference-semantic-conventions/src/openinference/semconv/trace/__init__.py",
    }
)
OPENINFERENCE_TYPE_MAP: Final = {
    "string": (("string",), "attribute"),
    "json string": (("string",), "attribute"),
    "integer": (("int64",), "attribute"),
    "float": (("double",), "attribute"),
    "boolean": (("boolean",), "attribute"),
    "list of floats": (("double[]",), "attribute"),
    "list of strings": (("string[]",), "attribute"),
    "list of objects": ((), "indexed_prefix"),
    "image object": ((), "object_prefix"),
    "string/integer": (("string", "int64"), "attribute"),
}
OPENINFERENCE_ATTRIBUTE_CLASSES: Final = frozenset(
    {
        "ResourceAttributes",
        "SpanAttributes",
        "MessageAttributes",
        "MessageContentAttributes",
        "ImageAttributes",
        "AudioAttributes",
        "DocumentAttributes",
        "RerankerAttributes",
        "EmbeddingAttributes",
        "ToolCallAttributes",
        "PromptAttributes",
        "ChoiceAttributes",
        "ToolAttributes",
    }
)
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{0,255}$")
DOMAIN_PATHS: Final = (
    "schemas/telemetry/v8/genai.yaml",
    "schemas/telemetry/v8/security.yaml",
    "schemas/telemetry/v8/operations.yaml",
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _extracted_tree_sha256(files: dict[str, bytes]) -> str:
    rows = [{"path": path, "sha256": _sha256(files[path])} for path in sorted(files)]
    return _sha256(b"DefenseClaw upstream extracted tree v1\x00" + _canonical_json(rows))


def _selection_sha256(attribute_ids: list[str]) -> str:
    return _sha256(_canonical_json(attribute_ids))


def _authored_extension_refs(root: Path) -> set[str]:
    refs: set[str] = set()
    for relative in DOMAIN_PATHS:
        document = load_yaml_strict(root / relative)
        extensions = document.get("attribute_extensions")
        if not isinstance(extensions, list):
            raise RegistryError(f"{relative}: attribute_extensions must be a sequence")
        for index, extension in enumerate(extensions):
            if not isinstance(extension, dict) or not isinstance(extension.get("ref"), str):
                raise RegistryError(f"{relative}.attribute_extensions[{index}]: missing ref")
            reference = extension["ref"]
            if reference in refs:
                raise RegistryError(f"attribute extension {reference}: duplicate authored selection")
            refs.add(reference)
    return refs


def _archive_url(repository: str, revision: str) -> str:
    return f"{repository.rstrip('/')}/archive/{revision}.tar.gz"


def _download(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "DefenseClaw-telemetry-registry-updater/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - pinned allowlist URL
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > MAX_ARCHIVE_BYTES:
                raise RegistryError("upstream archive exceeds maximum size")
            payload = response.read(MAX_ARCHIVE_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise RegistryError("failed to download pinned upstream archive") from exc
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise RegistryError("upstream archive exceeds maximum size")
    return payload


def _archive_files(payload: bytes) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise RegistryError("upstream archive contains too many entries")
            roots = {member.name.split("/", 1)[0] for member in members if member.name}
            if len(roots) != 1:
                raise RegistryError("upstream archive must have one root directory")
            root = next(iter(roots)) + "/"
            expanded_bytes = 0
            for member in members:
                if member.isdir() or member.issym() or member.islnk():
                    continue
                if not member.isfile():
                    raise RegistryError("upstream archive contains a non-regular entry")
                if not member.name.startswith(root):
                    raise RegistryError("upstream archive entry escapes root")
                relative = member.name[len(root) :]
                path = Path(relative)
                if path.is_absolute() or ".." in path.parts or not relative:
                    raise RegistryError("upstream archive contains an unsafe path")
                if member.size > MAX_SOURCE_FILE_BYTES:
                    raise RegistryError("upstream source file exceeds maximum size")
                expanded_bytes += member.size
                if expanded_bytes > MAX_EXPANDED_BYTES:
                    raise RegistryError("upstream archive exceeds maximum expanded size")
                stream = archive.extractfile(member)
                if stream is None:
                    raise RegistryError("upstream archive member cannot be read")
                normalized = path.as_posix()
                if normalized in result:
                    raise RegistryError("upstream archive contains duplicate paths")
                content = stream.read(MAX_SOURCE_FILE_BYTES + 1)
                if len(content) != member.size:
                    raise RegistryError("upstream archive member size is inconsistent")
                result[normalized] = content
    except (tarfile.TarError, OSError) as exc:
        raise RegistryError("invalid upstream tar archive") from exc
    if not result:
        raise RegistryError("upstream archive contains no source files")
    return result


def _json_pointer(parts: tuple[str, ...]) -> str:
    return "/" + "/".join(part.replace("~", "~0").replace("/", "~1") for part in parts)


def _normalized_type(value: Any) -> tuple[str | None, tuple[str, ...]]:
    if isinstance(value, str):
        token = value.strip().lower().replace(" ", "")
        aliases = {
            "str": "string",
            "string": "string",
            "bool": "boolean",
            "boolean": "boolean",
            "int": "int64",
            "integer": "int64",
            "int64": "int64",
            "double": "double",
            "float": "double",
            "float64": "double",
            "bytes": "bytes",
            "string[]": "string[]",
            "boolean[]": "boolean[]",
            "int64[]": "int64[]",
            "double[]": "double[]",
            "template[string]": "string",
            "template[int]": "int64",
            "any": "any",
        }
        if token in aliases:
            return aliases[token], ()
        if token.startswith("enum"):
            return "string", ()
        return None, ()
    if isinstance(value, dict):
        members = value.get("members")
        if isinstance(members, list):
            enum: list[str] = []
            for member in members:
                if isinstance(member, dict):
                    candidate = member.get("value") or member.get("id")
                else:
                    candidate = member
                if isinstance(candidate, str):
                    enum.append(candidate)
            return "string", tuple(sorted(set(enum)))
        for key in ("type", "template"):
            if key in value:
                return _normalized_type(value[key])
    return None, ()


def _yaml_attributes(path: str, payload: bytes) -> list[dict[str, Any]]:
    try:
        text = payload.decode("utf-8")
        root = yaml.safe_load(text)
    except UnicodeDecodeError as exc:
        raise RegistryError(f"upstream YAML source {path}: invalid UTF-8") from exc
    except yaml.YAMLError as exc:
        raise RegistryError(f"upstream YAML source {path}: parse failure") from exc
    result: list[dict[str, Any]] = []

    def walk(value: Any, pointer: tuple[str, ...], stability: str) -> None:
        if isinstance(value, dict):
            current_stability = value.get("stability", stability)
            if current_stability not in {"development", "stable", "deprecated"}:
                current_stability = stability
            attribute_id = value.get("id") or value.get("key")
            if "attributes" in pointer and isinstance(attribute_id, str) and "type" in value:
                attribute_type, enum = _normalized_type(value["type"])
                if attribute_type is not None and _ID.fullmatch(attribute_id):
                    deprecated = current_stability == "deprecated" or bool(value.get("deprecated"))
                    attribute_shape = "any_value" if attribute_type == "any" else "attribute"
                    result.append(
                        {
                            "id": attribute_id,
                            "allowed_types": [] if attribute_shape == "any_value" else [attribute_type],
                            "shape": attribute_shape,
                            "stability": "deprecated" if deprecated else current_stability,
                            "stability_source": "upstream",
                            "source_pointer": f"{path}#{_json_pointer(pointer)}",
                            "enum": list(enum),
                            "deprecated": deprecated,
                        }
                    )
            for key, item in value.items():
                walk(item, (*pointer, str(key)), current_stability)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, (*pointer, str(index)), stability)

    walk(root, (), "development")
    return result


def _python_attributes(path: str, payload: bytes) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(payload.decode("utf-8"), filename=path)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise RegistryError(f"openinference: invalid canonical constants source {path}") from exc
    result: list[dict[str, Any]] = []
    for class_node in tree.body:
        if not isinstance(class_node, ast.ClassDef) or class_node.name not in OPENINFERENCE_ATTRIBUTE_CLASSES:
            continue
        for node in class_node.body:
            value: str | None = None
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                candidate = node.value
                if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
                    value = candidate.value
            if value is None or not _ID.fullmatch(value):
                continue
            result.append(
                {
                    "id": value,
                    "allowed_types": ["string"],
                    "shape": "attribute",
                    "stability": "stable",
                    "stability_source": "released_package_policy",
                    "source_pointer": f"{path}#L{getattr(node, 'lineno', 0)}",
                    "enum": [],
                    "deprecated": False,
                }
            )
    return result


def _openinference_markdown_attributes(path: str, payload: bytes) -> dict[str, dict[str, Any]]:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise RegistryError("openinference: semantic-convention specification is not UTF-8") from exc
    headings = [index for index, line in enumerate(lines) if line == "## Reserved Attributes"]
    if len(headings) != 1:
        raise RegistryError("openinference: expected one Reserved Attributes heading")
    def table_cells(line: str, line_number: int) -> list[str]:
        line = line.strip()
        if not line.startswith("|") or not line.endswith("|"):
            raise RegistryError(
                f"openinference: malformed Reserved Attributes table row at line {line_number}"
            )
        cells = [cell.strip() for cell in line.split("|")]
        if cells[0] or cells[-1] or len(cells) != 6:
            raise RegistryError(
                f"openinference: malformed Reserved Attributes table columns at line {line_number}"
            )
        return cells[1:-1]

    next_heading = next(
        (
            index
            for index in range(headings[0] + 1, len(lines))
            if lines[index].startswith("## ")
        ),
        len(lines),
    )
    header_candidates = [
        index
        for index in range(headings[0] + 1, next_heading)
        if lines[index].strip().startswith("| Attribute")
    ]
    if len(header_candidates) != 1:
        raise RegistryError("openinference: expected one Reserved Attributes table")
    header_index = header_candidates[0]
    if header_index + 1 >= len(lines):
        raise RegistryError("openinference: Reserved Attributes table is incomplete")
    if table_cells(lines[header_index], header_index + 1) != [
        "Attribute",
        "Type",
        "Example",
        "Description",
    ]:
        raise RegistryError("openinference: unexpected Reserved Attributes table header")
    separator = table_cells(lines[header_index + 1], header_index + 2)
    if any(re.fullmatch(r":?-{3,}:?", cell) is None for cell in separator):
        raise RegistryError("openinference: malformed Reserved Attributes table separator")

    result: dict[str, dict[str, Any]] = {}
    row_index = header_index + 2
    while row_index < len(lines) and lines[row_index].strip().startswith("|"):
        cells = table_cells(lines[row_index], row_index + 1)
        line_number = row_index + 1
        if not (cells[0].startswith("`") and cells[0].endswith("`")):
            raise RegistryError("openinference: malformed Reserved Attributes attribute name")
        attribute_id = cells[0][1:-1]
        if not _ID.fullmatch(attribute_id):
            raise RegistryError("openinference: malformed Reserved Attributes attribute ID")
        type_name = re.sub(r"<[^>]+>", "", cells[1]).replace("†", "").strip().lower()
        type_name = " ".join(type_name.split())
        type_definition = OPENINFERENCE_TYPE_MAP.get(type_name)
        if type_definition is None:
            raise RegistryError(
                f"openinference attribute {attribute_id}: unsupported Reserved Attributes type"
            )
        allowed_types, attribute_shape = type_definition
        item = {
            "id": attribute_id,
            "allowed_types": list(allowed_types),
            "shape": attribute_shape,
            "stability": "stable",
            "stability_source": "released_package_policy",
            "source_pointer": f"{path}#L{line_number}",
            "enum": [],
            "deprecated": False,
        }
        existing = result.get(attribute_id)
        if existing is not None:
            raise RegistryError(f"openinference attribute {attribute_id}: duplicate specification row")
        result[attribute_id] = item
        row_index += 1
    if not result:
        raise RegistryError("openinference: Reserved Attributes table is empty")
    return result


def _openinference_attributes(
    files: dict[str, bytes],
    expected_version: str,
) -> tuple[list[dict[str, Any]], set[str]]:
    missing_sources = OPENINFERENCE_SEMCONV_FILES - files.keys()
    if missing_sources:
        raise RegistryError("openinference: authoritative semantic-convention sources are incomplete")
    version_path = "python/openinference-semantic-conventions/src/openinference/semconv/version.py"
    try:
        version_tree = ast.parse(files[version_path].decode("utf-8"), filename=version_path)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise RegistryError("openinference: invalid semantic-convention version source") from exc
    versions = [
        node.value.value
        for node in version_tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    if versions != [expected_version]:
        raise RegistryError("openinference: semantic-convention package version does not match lock")
    constants: dict[str, dict[str, Any]] = {}
    constants_by_path: dict[str, dict[str, dict[str, Any]]] = {}
    for path in sorted(OPENINFERENCE_PYTHON_FILES):
        path_constants: dict[str, dict[str, Any]] = {}
        for item in _python_attributes(path, files[path]):
            if item["id"] in path_constants or item["id"] in constants:
                raise RegistryError(f"openinference attribute {item['id']}: duplicate canonical constant")
            path_constants[item["id"]] = item
            constants[item["id"]] = item
        constants_by_path[path] = path_constants
    if not constants:
        raise RegistryError("openinference: no canonical constants discovered")
    specification_path = "spec/semantic_conventions.md"
    specification = _openinference_markdown_attributes(
        specification_path,
        files[specification_path],
    )
    trace_path = "python/openinference-semantic-conventions/src/openinference/semconv/trace/__init__.py"
    trace_ids = set(constants_by_path[trace_path])
    specification_ids = set(specification)
    direct_ids = trace_ids & specification_ids
    if not direct_ids:
        raise RegistryError("openinference: no canonical attributes shared by package and specification")
    attributes = [
        specification[attribute_id]
        for attribute_id in sorted(direct_ids)
    ]
    project_name = constants.get("openinference.project.name")
    if project_name is None or not project_name["source_pointer"].startswith(
        "python/openinference-semantic-conventions/src/openinference/semconv/resource/__init__.py#"
    ):
        raise RegistryError("openinference: resource project-name convention is missing")
    project_name = dict(project_name)
    project_name["allowed_types"] = ["string"]
    project_name["shape"] = "attribute"
    attributes.append(project_name)
    attributes.sort(key=lambda item: item["id"])
    if not attributes:
        raise RegistryError("openinference: no canonical semantic attributes discovered")
    return attributes, set(OPENINFERENCE_SEMCONV_FILES)


def _normalized_inventory(
    dependency: dict[str, Any],
    files: dict[str, bytes],
) -> tuple[list[dict[str, Any]], set[str]]:
    if dependency["id"] == "openinference":
        candidates, contributing = _openinference_attributes(files, dependency["version"])
    else:
        candidates = []
        contributing = set()
    for path in sorted(files):
        if dependency["id"] == "openinference":
            continue
        suffix = Path(path).suffix.lower()
        if suffix in {".yaml", ".yml"}:
            extracted = _yaml_attributes(path, files[path])
        else:
            extracted = []
        if extracted:
            candidates.extend(extracted)
            contributing.add(path)
    attributes: dict[str, dict[str, Any]] = {}
    for item in candidates:
        current = attributes.get(item["id"])
        if current is None:
            attributes[item["id"]] = item
            continue
        comparable = (
            item["allowed_types"],
            item["shape"],
            item["stability"],
            item["stability_source"],
            item["enum"],
            item["deprecated"],
        )
        existing = (
            current["allowed_types"],
            current["shape"],
            current["stability"],
            current["stability_source"],
            current["enum"],
            current["deprecated"],
        )
        if comparable != existing:
            raise RegistryError(f"upstream attribute {item['id']}: inconsistent definitions")
        if item["source_pointer"] < current["source_pointer"]:
            attributes[item["id"]] = item
    if not attributes:
        raise RegistryError(f"{dependency['id']}: no semantic attributes discovered")
    return [attributes[key] for key in sorted(attributes)], contributing


def _render_selected_snapshot(
    dependency: dict[str, Any],
    archive_url: str,
    archive_payload: bytes,
    files: dict[str, bytes],
    attributes: list[dict[str, Any]],
    contributing: set[str],
    selected_ids: set[str],
) -> bytes:
    by_id = {item["id"]: item for item in attributes}
    missing = selected_ids - by_id.keys()
    if missing:
        raise RegistryError(f"{dependency['id']}: selected attributes are absent upstream: {sorted(missing)}")
    selected_attributes = [by_id[attribute_id] for attribute_id in sorted(selected_ids)]
    selected_sources = {item["source_pointer"].split("#", 1)[0] for item in selected_attributes}
    if not selected_sources.issubset(contributing):
        raise RegistryError(f"{dependency['id']}: selected source provenance is incomplete")
    source_files = [
        {"path": path, "sha256": _sha256(files[path])}
        for path in sorted(selected_sources)
    ]
    full_source_files = [
        {"path": path, "sha256": _sha256(files[path])}
        for path in sorted(contributing)
    ]
    full_inventory_sha256 = _sha256(
        b"DefenseClaw normalized upstream inventory v1\x00"
        + _canonical_json({"source_files": full_source_files, "attributes": attributes})
    )
    selection_policy = (
        "runtime-profile-vocabulary-v1"
        if dependency["id"] == "openinference"
        else "authored-extension-closure-v1"
    )
    document = {
        "format_version": 2,
        "format": NORMALIZED_SNAPSHOT_FORMAT,
        "dependency_id": dependency["id"],
        "repository": dependency["repository"],
        "revision": dependency["revision"],
        "source_archive": {"url": archive_url, "sha256": _sha256(archive_payload)},
        "source_tree_sha256": _extracted_tree_sha256(files),
        "full_normalized_inventory_sha256": full_inventory_sha256,
        "selection": {
            "policy": selection_policy,
            "attribute_ids_sha256": _selection_sha256(sorted(selected_ids)),
        },
        "source_files": source_files,
        "attributes": selected_attributes,
    }
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _structural_input_local_path(revision: str, upstream_path: str) -> str:
    return f"schemas/telemetry/v8/upstream/otel-genai-{revision}/{upstream_path}"


def _validate_structural_input_lock(dependency: dict[str, Any]) -> None:
    raw_inputs = dependency.get("structural_inputs")
    if not isinstance(raw_inputs, list) or len(raw_inputs) != len(OTEL_GENAI_STRUCTURAL_INPUTS):
        raise RegistryError("otel_genai: structural inputs must contain the exact pinned inventory")
    revision = dependency["revision"]
    for index, (item, (expected_upstream_path, expected_digest)) in enumerate(
        zip(raw_inputs, OTEL_GENAI_STRUCTURAL_INPUTS, strict=True)
    ):
        item_path = f"otel_genai.structural_inputs[{index}]"
        if not isinstance(item, dict) or set(item) != {"upstream_path", "path", "sha256"}:
            raise RegistryError(f"{item_path}: unsupported shape")
        expected_local_path = _structural_input_local_path(revision, expected_upstream_path)
        if item["upstream_path"] != expected_upstream_path:
            raise RegistryError(f"{item_path}.upstream_path: unexpected path or order")
        if item["path"] != expected_local_path:
            raise RegistryError(f"{item_path}.path: must be revision-qualified and repository-relative")
        if item["sha256"] != expected_digest:
            raise RegistryError(f"{item_path}.sha256: does not match the pinned upstream bytes")


def _load_lock(
    path: Path,
    raw: bytes | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    document = load_yaml_strict(path) if raw is None else _parse_yaml_strict_bytes(path, raw)
    schema_version = document.get("schema_version")
    if (
        set(document) != {"schema_version", "dependencies"}
        or type(schema_version) is not int
        or schema_version != 1
    ):
        raise RegistryError("semconv lock has unsupported shape")
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, list):
        raise RegistryError("semconv lock dependencies must be a sequence")
    ids = tuple(item.get("id") for item in dependencies if isinstance(item, dict))
    if ids != EXPECTED_DEPENDENCIES:
        raise RegistryError("semconv lock dependencies are not in canonical order")
    output_paths: set[str] = set()
    for item in dependencies:
        if not isinstance(item, dict):
            raise RegistryError("semconv dependency has unsupported shape")
        expected_keys = {
            "id",
            "repository",
            "version",
            "profile_id",
            "revision",
            "snapshot",
        }
        if item.get("id") == "otel_genai":
            expected_keys.add("structural_inputs")
        if set(item) != expected_keys:
            raise RegistryError("semconv dependency has unsupported shape")
        for field in ("id", "repository", "version", "profile_id", "revision"):
            if not isinstance(item[field], str) or not item[field]:
                raise RegistryError(f"semconv dependency {field} must be a nonempty string")
        if item["repository"] != ALLOWED_REPOSITORIES[item["id"]]:
            raise RegistryError(f"{item['id']}: repository is not the primary allowlisted upstream")
        if len(item["version"].encode("utf-8")) > 4096:
            raise RegistryError(f"{item['id']}: version exceeds the compiler string bound")
        if (
            not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:/-]{0,255}", item["profile_id"])
            or item["profile_id"] != EXPECTED_PROFILE_IDS[item["id"]]
        ):
            raise RegistryError(f"{item['id']}: profile_id does not match the pinned semantic profile")
        if not re.fullmatch(r"[0-9a-f]{40}", item["revision"]):
            raise RegistryError(f"{item['id']}: revision must be an immutable commit")
        snapshot = item["snapshot"]
        if not isinstance(snapshot, dict) or set(snapshot) != {"path", "format", "sha256"}:
            raise RegistryError(f"{item['id']}: snapshot has unsupported shape")
        snapshot_path = _canonical_repository_output_path(
            snapshot["path"],
            prefix="schemas/telemetry/v8/upstream",
        )
        if snapshot_path in output_paths:
            raise RegistryError("semconv lock has duplicate upstream output paths")
        output_paths.add(snapshot_path)
        # The updater is the one intentional bridge from a full v1 snapshot to
        # a selected v2 snapshot. The offline compiler accepts only v2.
        if snapshot["format"] not in {
            LEGACY_NORMALIZED_SNAPSHOT_FORMAT,
            NORMALIZED_SNAPSHOT_FORMAT,
        }:
            raise RegistryError(f"{item['id']}: snapshot format is unsupported")
        if not isinstance(snapshot["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", snapshot["sha256"]):
            raise RegistryError(f"{item['id']}: snapshot sha256 must be lowercase hexadecimal")
        if item["id"] == "otel_genai":
            _validate_structural_input_lock(item)
            for structural_input in item["structural_inputs"]:
                structural_path = structural_input["path"]
                if structural_path in output_paths:
                    raise RegistryError("semconv lock has duplicate upstream output paths")
                output_paths.add(structural_path)
    return document, dependencies


def _candidate_lock_references(
    dependencies: list[dict[str, Any]],
) -> tuple[tuple[str, str], ...]:
    references: list[tuple[str, str]] = []
    for dependency in dependencies:
        snapshot = dependency["snapshot"]
        references.append((snapshot["path"], snapshot["sha256"]))
        for structural_input in dependency.get("structural_inputs", ()):
            references.append((structural_input["path"], structural_input["sha256"]))
    return tuple(references)


def _render_lock(document: dict[str, Any]) -> bytes:
    return yaml.safe_dump(
        document,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    ).encode("utf-8")


def _archive_overrides(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise RegistryError("--archive must use dependency=path")
        dependency, path = value.split("=", 1)
        if dependency not in EXPECTED_DEPENDENCIES or dependency in result:
            raise RegistryError("--archive has an unknown or duplicate dependency")
        result[dependency] = Path(path)
    return result


def _validate_structural_json(upstream_path: str, raw: bytes) -> None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RegistryError(f"{upstream_path}: invalid UTF-8") from exc
    if text.startswith("\ufeff"):
        raise RegistryError(f"{upstream_path}: UTF-8 BOM is not allowed")

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
                raise RegistryError(f"{upstream_path}: JSON nesting exceeds the parser limit")
        elif character in "]}":
            depth = max(0, depth - 1)

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise RegistryError(f"{upstream_path}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_nonfinite_constant(_value: str) -> None:
        raise RegistryError(f"{upstream_path}: invalid non-finite JSON number")

    try:
        document = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=reject_nonfinite_constant,
        )
    except RegistryError:
        raise
    except RecursionError as exc:
        raise RegistryError(f"{upstream_path}: invalid JSON nesting") from exc
    except json.JSONDecodeError as exc:
        raise RegistryError(f"{upstream_path}: invalid JSON") from exc
    if not isinstance(document, dict):
        raise RegistryError(f"{upstream_path}: document root must be an object")


def _canonical_repository_output_path(value: str, *, prefix: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise RegistryError("telemetry upstream output path is not canonical POSIX")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise RegistryError("telemetry upstream output path is not valid UTF-8") from exc
    if len(encoded) > 4096:
        raise RegistryError("telemetry upstream output path exceeds the compiler string bound")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or value.endswith("/")
        or "//" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise RegistryError("telemetry upstream output path is not canonical POSIX")
    prefix_parts = PurePosixPath(prefix).parts
    if path.parts[: len(prefix_parts)] != prefix_parts or len(path.parts) <= len(prefix_parts):
        raise RegistryError(f"telemetry upstream output path leaves {prefix}")
    return value


def _structural_input_outputs(
    dependency: dict[str, Any],
    files: dict[str, bytes],
) -> dict[str, bytes]:
    if dependency["id"] != "otel_genai":
        return {}
    rendered: dict[str, bytes] = {}
    for item in dependency["structural_inputs"]:
        upstream_path = item["upstream_path"]
        raw = files.get(upstream_path)
        if raw is None:
            raise RegistryError(f"{upstream_path}: pinned structural input is missing from the archive")
        if _sha256(raw) != item["sha256"]:
            raise RegistryError(f"{upstream_path}: pinned structural input digest mismatch")
        _validate_structural_json(upstream_path, raw)
        target = _canonical_repository_output_path(
            item["path"],
            prefix="schemas/telemetry/v8/upstream",
        )
        if target in rendered:
            raise RegistryError("otel_genai: duplicate structural input output path")
        rendered[target] = raw
    return rendered


def _directory_open_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RegistryError("telemetry upstream update requires O_NOFOLLOW")
    return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW


@contextlib.contextmanager
def _directory_descriptor(path: Path):  # type: ignore[no-untyped-def]
    absolute = path.absolute()
    flags = _directory_open_flags()
    descriptor = os.open(absolute.anchor, flags)
    try:
        try:
            for part in absolute.parts[1:]:
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise RegistryError("telemetry upstream repository root is not a directory")
        except OSError as exc:
            raise RegistryError("telemetry upstream directory chain is missing or unsafe") from exc
        yield descriptor
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def _repository_update_lock(root: Path):  # type: ignore[no-untyped-def]
    with _PROCESS_UPDATE_LOCK:
        with _directory_descriptor(root) as root_descriptor:
            try:
                fcntl.flock(root_descriptor, fcntl.LOCK_EX)
            except OSError as exc:
                raise RegistryError("cannot acquire telemetry upstream repository lock") from exc
            # Closing the directory descriptor is the authoritative advisory
            # lock release. Avoid a redundant LOCK_UN syscall whose failure
            # could falsely report that an already committed update failed.
            yield root_descriptor


def _open_relative_directory(
    root_descriptor: int,
    parts: tuple[str, ...],
    *,
    create: bool,
    mode: int,
    created: dict[tuple[str, ...], tuple[int, int]] | None = None,
) -> int:
    flags = _directory_open_flags()
    descriptor = os.dup(root_descriptor)
    prefix: list[str] = []
    try:
        for part in parts:
            prefix.append(part)
            try:
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, mode=mode, dir_fd=descriptor)
                os.fsync(descriptor)
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
                os.fchmod(next_descriptor, mode)
                os.fsync(next_descriptor)
                if created is not None:
                    metadata = os.fstat(next_descriptor)
                    created[tuple(prefix)] = (metadata.st_dev, metadata.st_ino)
            metadata = os.fstat(next_descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_descriptor)
                raise RegistryError("telemetry upstream parent is not a real directory")
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise RegistryError("telemetry upstream directory component is missing or unsafe") from exc
    except BaseException:
        os.close(descriptor)
        raise


def _open_parent_directory(
    root_descriptor: int,
    relative: str,
    *,
    create: bool,
    mode: int,
    created: dict[tuple[str, ...], tuple[int, int]] | None = None,
) -> tuple[int, str]:
    parts = PurePosixPath(relative).parts
    return (
        _open_relative_directory(
            root_descriptor,
            parts[:-1],
            create=create,
            mode=mode,
            created=created,
        ),
        parts[-1],
    )


def _entry_metadata(parent_descriptor: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _regular_identity(metadata: os.stat_result, *, require_single_link: bool) -> tuple[int, int]:
    if not stat.S_ISREG(metadata.st_mode) or (require_single_link and metadata.st_nlink != 1):
        raise RegistryError("telemetry upstream target is not a safe regular file")
    return metadata.st_dev, metadata.st_ino


def _read_regular_entry(
    parent_descriptor: int,
    name: str,
    *,
    max_bytes: int,
) -> tuple[tuple[int, int], bytes]:
    entry_before = _entry_metadata(parent_descriptor, name)
    if entry_before is None:
        raise RegistryError("telemetry upstream repository file is missing")
    identity = _regular_identity(entry_before, require_single_link=True)
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_descriptor,
    )
    payload = bytearray()
    too_large = False
    try:
        opened_before = os.fstat(descriptor)
        if _regular_identity(opened_before, require_single_link=True) != identity:
            raise RegistryError("telemetry upstream repository file changed while opening")
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes - len(payload) + 1))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > max_bytes:
                too_large = True
                break
        opened_after = os.fstat(descriptor)
        if _regular_identity(opened_after, require_single_link=True) != identity:
            raise RegistryError("telemetry upstream repository file changed while reading")
    finally:
        os.close(descriptor)
    entry_after = _entry_metadata(parent_descriptor, name)
    if (
        entry_after is None
        or _regular_identity(entry_after, require_single_link=True) != identity
    ):
        raise RegistryError("telemetry upstream repository file changed after reading")
    if too_large:
        raise RegistryError("telemetry upstream repository file exceeds the read limit")
    return identity, bytes(payload)


def _read_repository_file(
    root_descriptor: int,
    relative: str,
    *,
    max_bytes: int,
) -> tuple[tuple[int, int], bytes]:
    parent_descriptor, name = _open_parent_directory(
        root_descriptor,
        relative,
        create=False,
        mode=0o755,
    )
    try:
        return _read_regular_entry(parent_descriptor, name, max_bytes=max_bytes)
    finally:
        os.close(parent_descriptor)


def _validate_repository_digest(
    root_descriptor: int,
    relative: str,
    expected_digest: str,
) -> None:
    parent_descriptor, name = _open_parent_directory(
        root_descriptor,
        relative,
        create=False,
        mode=0o755,
    )
    descriptor: int | None = None
    try:
        entry_before = _entry_metadata(parent_descriptor, name)
        if entry_before is None:
            raise RegistryError(f"telemetry upstream candidate reference is missing: {relative}")
        identity = _regular_identity(entry_before, require_single_link=True)
        if entry_before.st_size > MAX_EXPANDED_BYTES:
            raise RegistryError(f"telemetry upstream candidate reference exceeds the read limit: {relative}")
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        opened_before = os.fstat(descriptor)
        if _regular_identity(opened_before, require_single_link=True) != identity:
            raise RegistryError("telemetry upstream candidate reference changed while opening")
        digest = hashlib.sha256()
        total = 0
        too_large = False
        while True:
            read_size = min(1024 * 1024, MAX_EXPANDED_BYTES - total + 1)
            chunk = os.read(descriptor, read_size)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            if total > MAX_EXPANDED_BYTES:
                too_large = True
                break
        opened_after = os.fstat(descriptor)
        if _regular_identity(opened_after, require_single_link=True) != identity:
            raise RegistryError("telemetry upstream candidate reference changed while reading")
        entry_after = _entry_metadata(parent_descriptor, name)
        if (
            entry_after is None
            or _regular_identity(entry_after, require_single_link=True) != identity
        ):
            raise RegistryError("telemetry upstream candidate reference changed after reading")
        if too_large:
            raise RegistryError(f"telemetry upstream candidate reference exceeds the read limit: {relative}")
        if digest.hexdigest() != expected_digest:
            raise RegistryError(f"telemetry upstream candidate reference digest mismatch: {relative}")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)


def _directory_identity(descriptor: int) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise RegistryError("telemetry upstream parent descriptor is not a directory")
    return metadata.st_dev, metadata.st_ino


def _validate_parent_binding(root_descriptor: int, state: dict[str, Any]) -> None:
    expected_identity = state["parent_identity"]
    if _directory_identity(state["parent_descriptor"]) != expected_identity:
        raise RegistryError("telemetry upstream held parent directory changed identity")
    current_descriptor = _open_relative_directory(
        root_descriptor,
        state["parent_parts"],
        create=False,
        mode=0o755,
    )
    try:
        if _directory_identity(current_descriptor) != expected_identity:
            raise RegistryError("telemetry upstream target parent left its canonical namespace")
    finally:
        os.close(current_descriptor)


def _validate_installed_target(root_descriptor: int, state: dict[str, Any]) -> None:
    _validate_parent_binding(root_descriptor, state)
    expected_identity = state["installed_identity"]
    expected_payload = state["expected_payload"]
    expected_digest = state["installed_sha256"]
    if expected_identity is None or not isinstance(expected_payload, bytes):
        raise RegistryError("telemetry upstream installed target state is incomplete")
    parent_descriptor = state["parent_descriptor"]
    name = PurePosixPath(state["relative"]).name
    entry_before = _entry_metadata(parent_descriptor, name)
    if (
        entry_before is None
        or _regular_identity(entry_before, require_single_link=True) != expected_identity
    ):
        raise RegistryError("telemetry upstream installed target changed before verification")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    matches = True
    digest = hashlib.sha256()
    offset = 0
    try:
        opened_before = os.fstat(descriptor)
        if _regular_identity(opened_before, require_single_link=True) != expected_identity:
            raise RegistryError("telemetry upstream installed target changed while opening")
        while True:
            read_size = min(1024 * 1024, max(1, len(expected_payload) - offset + 1))
            chunk = os.read(descriptor, read_size)
            if not chunk:
                break
            digest.update(chunk)
            end = offset + len(chunk)
            if end > len(expected_payload) or chunk != expected_payload[offset:end]:
                matches = False
            offset = end
            if offset > len(expected_payload):
                break
        opened_after = os.fstat(descriptor)
        if _regular_identity(opened_after, require_single_link=True) != expected_identity:
            raise RegistryError("telemetry upstream installed target changed while reading")
    finally:
        os.close(descriptor)

    entry_after = _entry_metadata(parent_descriptor, name)
    if (
        entry_after is None
        or _regular_identity(entry_after, require_single_link=True) != expected_identity
    ):
        raise RegistryError("telemetry upstream installed target changed after verification")
    if offset != len(expected_payload) or not matches or digest.hexdigest() != expected_digest:
        raise RegistryError("telemetry upstream installed target content changed")


def _validate_original_lock(
    root_descriptor: int,
    state: dict[str, Any],
    expected_identity: tuple[int, int],
    expected_payload: bytes,
) -> None:
    _validate_parent_binding(root_descriptor, state)
    parent_descriptor = state["parent_descriptor"]
    name = PurePosixPath(state["relative"]).name
    identity, payload = _read_regular_entry(
        parent_descriptor,
        name,
        max_bytes=MAX_LOCK_BYTES,
    )
    if identity != expected_identity or payload != expected_payload:
        raise RegistryError("telemetry upstream lock changed since refresh derivation")


def _validate_candidate_references(
    root_descriptor: int,
    references: tuple[tuple[str, str], ...],
) -> None:
    for relative, expected_digest in references:
        _validate_repository_digest(root_descriptor, relative, expected_digest)


def _write_staged_file(
    transaction_descriptor: int,
    relative: str,
    payload: bytes,
    mode: int,
) -> None:
    parent_descriptor, name = _open_parent_directory(
        transaction_descriptor,
        f"new/{relative}",
        create=True,
        mode=0o700,
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent_descriptor)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent_descriptor)
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(name, dir_fd=parent_descriptor)
        raise
    finally:
        os.close(parent_descriptor)


def _create_transaction_directory(
    root_descriptor: int,
) -> tuple[str, int, tuple[int, int]]:
    flags = _directory_open_flags()
    for _attempt in range(32):
        name = f".telemetry-upstream-update-{secrets.token_hex(16)}"
        descriptor: int | None = None
        identity: tuple[int, int] | None = None
        try:
            os.mkdir(name, mode=0o700, dir_fd=root_descriptor)
        except FileExistsError:
            continue
        try:
            created = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(created.st_mode):
                raise RegistryError("telemetry upstream transaction entry is not a directory")
            identity = (created.st_dev, created.st_ino)
            os.fsync(root_descriptor)
            descriptor = os.open(name, flags, dir_fd=root_descriptor)
            if _directory_identity(descriptor) != identity:
                raise RegistryError("telemetry upstream transaction directory changed during initialization")
            os.fchmod(descriptor, 0o700)
            os.fsync(descriptor)
            return name, descriptor, identity
        except BaseException as exc:
            if descriptor is not None:
                os.close(descriptor)
            if identity is not None:
                try:
                    _remove_tree_at(root_descriptor, name, identity)
                except BaseException as cleanup_exc:
                    raise RegistryError(
                        "cannot initialize telemetry upstream transaction directory; cleanup failed"
                    ) from cleanup_exc
            if not isinstance(exc, Exception):
                raise
            raise RegistryError("cannot initialize telemetry upstream transaction directory") from exc
    raise RegistryError("cannot allocate telemetry upstream transaction directory")


def _remove_tree_at(
    parent_descriptor: int,
    name: str,
    expected_identity: tuple[int, int],
) -> None:
    flags = _directory_open_flags()
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        opened = os.fstat(descriptor)
        entry = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != expected_identity or (
            entry.st_dev,
            entry.st_ino,
        ) != expected_identity:
            raise RegistryError("telemetry upstream transaction directory was replaced")
        for child in tuple(os.listdir(descriptor)):
            metadata = os.stat(child, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                _remove_tree_at(
                    descriptor,
                    child,
                    (metadata.st_dev, metadata.st_ino),
                )
            else:
                os.unlink(child, dir_fd=descriptor)
        os.fsync(descriptor)
        entry = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (entry.st_dev, entry.st_ino) != expected_identity:
            raise RegistryError("telemetry upstream transaction directory changed during cleanup")
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent_descriptor)
    os.fsync(parent_descriptor)


def _remove_created_directories(
    root_descriptor: int,
    created: dict[tuple[str, ...], tuple[int, int]],
) -> None:
    for parts in sorted(created, key=lambda item: (len(item), item), reverse=True):
        parent_descriptor = _open_relative_directory(
            root_descriptor,
            parts[:-1],
            create=False,
            mode=0o755,
        )
        try:
            metadata = os.stat(parts[-1], dir_fd=parent_descriptor, follow_symlinks=False)
            if (metadata.st_dev, metadata.st_ino) != created[parts]:
                raise RegistryError("telemetry upstream created directory changed during rollback")
            os.rmdir(parts[-1], dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)


def _rollback_rendered(
    transaction_descriptor: int,
    states: list[dict[str, Any]],
) -> None:
    for state in reversed(states):
        relative = state["relative"]
        parent_descriptor = state["parent_descriptor"]
        name = PurePosixPath(relative).name
        backup_descriptor, backup_name = _open_parent_directory(
            transaction_descriptor,
            f"backup/{relative}",
            create=True,
            mode=0o700,
        )
        try:
            target = _entry_metadata(parent_descriptor, name)
            prior_identity = state["prior_identity"]
            installed_identity = state["installed_identity"]
            if target is not None and installed_identity is not None:
                if _regular_identity(target, require_single_link=False) != installed_identity:
                    raise RegistryError("telemetry upstream target changed during rollback")
                os.unlink(name, dir_fd=parent_descriptor)
                os.fsync(parent_descriptor)
                target = None
            backup = _entry_metadata(backup_descriptor, backup_name)
            if prior_identity is None:
                if target is not None or backup is not None:
                    raise RegistryError("telemetry upstream new target could not be rolled back")
                continue
            if target is not None:
                if _regular_identity(target, require_single_link=False) != prior_identity:
                    raise RegistryError("telemetry upstream prior target changed during rollback")
            elif backup is not None:
                if _regular_identity(backup, require_single_link=False) != prior_identity:
                    raise RegistryError("telemetry upstream backup changed during rollback")
                os.link(
                    backup_name,
                    name,
                    src_dir_fd=backup_descriptor,
                    dst_dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                os.fsync(parent_descriptor)
                target = _entry_metadata(parent_descriptor, name)
                if target is None or _regular_identity(target, require_single_link=False) != prior_identity:
                    raise RegistryError("telemetry upstream prior target restore was not exact")
            else:
                raise RegistryError("telemetry upstream prior target and backup are both missing")
            if backup is not None:
                os.unlink(backup_name, dir_fd=backup_descriptor)
                os.fsync(backup_descriptor)
        finally:
            os.close(backup_descriptor)


def _install_rendered(
    root: Path,
    rendered: dict[str, bytes],
    lock_relative: str,
    *,
    expected_lock_identity: tuple[int, int] | None = None,
    expected_lock_payload: bytes | None = None,
    candidate_references: tuple[tuple[str, str], ...] = (),
) -> None:
    """Install a complete refresh set and restore every prior byte on failure.

    Snapshots and structural inputs are installed before the lock. A process
    interruption can therefore only leave a lock/input digest mismatch, which
    the normal compiler rejects closed. Synchronous failures before the final
    lock fsync and all-target validation are rolled back. That validation is
    the commit point; subsequent private-transaction cleanup failures report
    explicitly that the update remains committed. Parent bindings are checked
    immediately around publication; as with any multi-directory filesystem
    transaction, repository writers must not mutate the namespace after the
    final binding check.
    """

    lock_relative = _canonical_repository_output_path(lock_relative, prefix="schemas/telemetry/v8")
    if lock_relative != "schemas/telemetry/v8/semconv.lock.yaml":
        raise RegistryError("telemetry upstream lock path is not canonical")
    if (expected_lock_identity is None) != (expected_lock_payload is None):
        raise RegistryError("telemetry upstream lock CAS state is incomplete")
    normalized_references: list[tuple[str, str]] = []
    reference_paths: set[str] = set()
    for relative, digest in candidate_references:
        normalized_relative = _canonical_repository_output_path(
            relative,
            prefix="schemas/telemetry/v8/upstream",
        )
        if normalized_relative in reference_paths or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RegistryError("telemetry upstream candidate reference is invalid")
        reference_paths.add(normalized_relative)
        normalized_references.append((normalized_relative, digest))
    candidate_references = tuple(normalized_references)
    normalized: dict[str, bytes] = {}
    for relative, payload in rendered.items():
        if relative == lock_relative:
            normalized_relative = lock_relative
        else:
            normalized_relative = _canonical_repository_output_path(
                relative,
                prefix="schemas/telemetry/v8/upstream",
            )
        if normalized_relative in normalized:
            raise RegistryError("telemetry upstream update has duplicate output paths")
        normalized[normalized_relative] = payload
    if lock_relative not in normalized:
        raise RegistryError("telemetry upstream update is missing its lock commit marker")
    targets = sorted(normalized, key=lambda item: (item == lock_relative, item))

    created_directories: dict[tuple[str, ...], tuple[int, int]] = {}
    states: list[dict[str, Any]] = []
    with _directory_descriptor(root) as root_descriptor:
        transaction_name, transaction_descriptor, transaction_identity = _create_transaction_directory(
            root_descriptor
        )
        remove_transaction = True
        committed = False
        try:
            for relative in targets:
                parent_descriptor, name = _open_parent_directory(
                    root_descriptor,
                    relative,
                    create=True,
                    mode=0o755,
                    created=created_directories,
                )
                try:
                    metadata = _entry_metadata(parent_descriptor, name)
                    prior_identity = None if metadata is None else _regular_identity(
                        metadata,
                        require_single_link=True,
                    )
                    mode = 0o644 if metadata is None else stat.S_IMODE(metadata.st_mode)
                except BaseException:
                    os.close(parent_descriptor)
                    raise
                state = {
                    "relative": relative,
                    "parent_descriptor": parent_descriptor,
                    "parent_parts": PurePosixPath(relative).parts[:-1],
                    "parent_identity": _directory_identity(parent_descriptor),
                    "prior_identity": prior_identity,
                    "installed_identity": None,
                    "installed_sha256": _sha256(normalized[relative]),
                    "expected_payload": normalized[relative],
                    "mode": mode,
                }
                states.append(state)
                _write_staged_file(
                    transaction_descriptor,
                    relative,
                    normalized[relative],
                    mode,
                )

            lock_state = states[-1]
            if lock_state["relative"] != lock_relative:
                raise RegistryError("telemetry upstream lock is not the final publication state")
            if expected_lock_identity is not None and expected_lock_payload is not None:
                _validate_original_lock(
                    root_descriptor,
                    lock_state,
                    expected_lock_identity,
                    expected_lock_payload,
                )

            for state in states:
                relative = state["relative"]
                parent_descriptor = state["parent_descriptor"]
                name = PurePosixPath(relative).name
                _validate_parent_binding(root_descriptor, state)
                if relative == lock_relative:
                    for candidate in states:
                        if candidate["installed_identity"] is None:
                            _validate_parent_binding(root_descriptor, candidate)
                        else:
                            _validate_installed_target(root_descriptor, candidate)
                    _validate_candidate_references(root_descriptor, candidate_references)
                    if expected_lock_identity is not None and expected_lock_payload is not None:
                        _validate_original_lock(
                            root_descriptor,
                            state,
                            expected_lock_identity,
                            expected_lock_payload,
                        )
                staged_descriptor, staged_name = _open_parent_directory(
                    transaction_descriptor,
                    f"new/{relative}",
                    create=False,
                    mode=0o700,
                )
                backup_descriptor, backup_name = _open_parent_directory(
                    transaction_descriptor,
                    f"backup/{relative}",
                    create=True,
                    mode=0o700,
                )
                try:
                    if (
                        relative == lock_relative
                        and expected_lock_identity is not None
                        and expected_lock_payload is not None
                    ):
                        _validate_original_lock(
                            root_descriptor,
                            state,
                            expected_lock_identity,
                            expected_lock_payload,
                        )
                    target = _entry_metadata(parent_descriptor, name)
                    prior_identity = state["prior_identity"]
                    if prior_identity is None:
                        if target is not None:
                            raise RegistryError("telemetry upstream target appeared during publication")
                    elif target is None or _regular_identity(target, require_single_link=True) != prior_identity:
                        raise RegistryError("telemetry upstream target changed during publication")
                    if _entry_metadata(backup_descriptor, backup_name) is not None:
                        raise RegistryError("telemetry upstream backup path collision")
                    if target is not None:
                        os.link(
                            name,
                            backup_name,
                            src_dir_fd=parent_descriptor,
                            dst_dir_fd=backup_descriptor,
                            follow_symlinks=False,
                        )
                        os.fsync(backup_descriptor)
                        linked = _entry_metadata(backup_descriptor, backup_name)
                        if linked is None or _regular_identity(linked, require_single_link=False) != prior_identity:
                            raise RegistryError("telemetry upstream backup is not exact")
                        current = _entry_metadata(parent_descriptor, name)
                        if current is None or _regular_identity(current, require_single_link=False) != prior_identity:
                            raise RegistryError("telemetry upstream target changed after backup")
                        os.unlink(name, dir_fd=parent_descriptor)
                        os.fsync(parent_descriptor)
                    staged = _entry_metadata(staged_descriptor, staged_name)
                    if staged is None:
                        raise RegistryError("telemetry upstream staged output disappeared")
                    staged_identity = _regular_identity(staged, require_single_link=True)
                    state["installed_identity"] = staged_identity
                    os.link(
                        staged_name,
                        name,
                        src_dir_fd=staged_descriptor,
                        dst_dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    os.fsync(parent_descriptor)
                    installed = _entry_metadata(parent_descriptor, name)
                    if installed is None or _regular_identity(installed, require_single_link=False) != staged_identity:
                        raise RegistryError("telemetry upstream installed output is not exact")
                    os.unlink(staged_name, dir_fd=staged_descriptor)
                    os.fsync(staged_descriptor)
                finally:
                    os.close(backup_descriptor)
                    os.close(staged_descriptor)
                if relative == lock_relative:
                    for candidate in states:
                        _validate_installed_target(root_descriptor, candidate)
                    _validate_candidate_references(root_descriptor, candidate_references)
            committed = True
        except BaseException as publication_exc:
            try:
                _rollback_rendered(transaction_descriptor, states)
                for state in states:
                    parent_descriptor = state.pop("parent_descriptor", None)
                    if parent_descriptor is not None:
                        os.close(parent_descriptor)
                states.clear()
                _remove_created_directories(root_descriptor, created_directories)
            except BaseException as rollback_exc:
                remove_transaction = False
                raise RegistryError(
                    "telemetry upstream rollback failed; transaction evidence was preserved"
                ) from rollback_exc
            if not isinstance(publication_exc, Exception):
                raise
            raise RegistryError(
                "telemetry upstream publication failed and was rolled back"
            ) from publication_exc
        finally:
            for state in states:
                parent_descriptor = state.pop("parent_descriptor", None)
                if parent_descriptor is not None:
                    os.close(parent_descriptor)
            os.close(transaction_descriptor)
            if remove_transaction:
                try:
                    _remove_tree_at(
                        root_descriptor,
                        transaction_name,
                        transaction_identity,
                    )
                except BaseException as cleanup_exc:
                    if committed:
                        raise RegistryError(
                            "telemetry upstream update committed; transaction cleanup failed"
                        ) from cleanup_exc
                    raise


def update(root: Path, selected: tuple[str, ...], overrides: dict[str, Path]) -> None:
    root = root.absolute()
    lock_relative = "schemas/telemetry/v8/semconv.lock.yaml"
    lock_path = root / lock_relative
    with _repository_update_lock(root) as lock_root_descriptor:
        original_lock_identity, original_lock_payload = _read_repository_file(
            lock_root_descriptor,
            lock_relative,
            max_bytes=MAX_LOCK_BYTES,
        )
        lock, dependencies = _load_lock(lock_path, original_lock_payload)
        extension_refs = _authored_extension_refs(root)
        selected_ids = {
            "otel_core": {reference for reference in extension_refs if not reference.startswith("gen_ai.")},
            "otel_genai": {reference for reference in extension_refs if reference.startswith("gen_ai.")},
            "openinference": set(REQUIRED_OPENINFERENCE_ATTRIBUTES),
        }
        if selected_ids["otel_core"] & selected_ids["otel_genai"]:
            raise RegistryError("authored OTel selection has overlapping ownership")
        if selected_ids["otel_core"] | selected_ids["otel_genai"] != extension_refs:
            raise RegistryError("authored OTel selection does not cover every extension")

        prepared: dict[
            str,
            tuple[
                dict[str, Any],
                str,
                bytes,
                dict[str, bytes],
                list[dict[str, Any]],
                set[str],
                dict[str, bytes],
            ],
        ] = {}
        for dependency in dependencies:
            if dependency["id"] not in selected:
                continue
            url = _archive_url(dependency["repository"], dependency["revision"])
            override = overrides.get(dependency["id"])
            payload = override.read_bytes() if override is not None else _download(url)
            files = _archive_files(payload)
            attributes, contributing = _normalized_inventory(dependency, files)
            structural_outputs = _structural_input_outputs(dependency, files)
            prepared[dependency["id"]] = (
                dependency,
                url,
                payload,
                files,
                attributes,
                contributing,
                structural_outputs,
            )

        rendered: dict[str, bytes] = {}
        for dependency in dependencies:
            prepared_dependency = prepared.get(dependency["id"])
            if prepared_dependency is None:
                continue
            (
                dependency,
                url,
                payload,
                files,
                attributes,
                contributing,
                structural_outputs,
            ) = prepared_dependency
            snapshot = _render_selected_snapshot(
                dependency,
                url,
                payload,
                files,
                attributes,
                contributing,
                selected_ids[dependency["id"]],
            )
            snapshot_path = _canonical_repository_output_path(
                dependency["snapshot"]["path"],
                prefix="schemas/telemetry/v8/upstream",
            )
            dependency["snapshot"]["format"] = NORMALIZED_SNAPSHOT_FORMAT
            dependency["snapshot"]["sha256"] = _sha256(snapshot)
            if snapshot_path in rendered:
                raise RegistryError("telemetry upstream update has duplicate output paths")
            rendered[snapshot_path] = snapshot
            for target, raw in structural_outputs.items():
                if target in rendered:
                    raise RegistryError("telemetry upstream update has duplicate output paths")
                rendered[target] = raw
        rendered[lock_relative] = _render_lock(lock)
        _install_rendered(
            root,
            rendered,
            lock_relative,
            expected_lock_identity=original_lock_identity,
            expected_lock_payload=original_lock_payload,
            candidate_references=_candidate_lock_references(dependencies),
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--dependency", action="append", choices=EXPECTED_DEPENDENCIES)
    parser.add_argument(
        "--archive",
        action="append",
        default=[],
        metavar="DEPENDENCY=PATH",
        help="use a local immutable archive (tests/reproducible review only)",
    )
    args = parser.parse_args(argv)
    try:
        selected = tuple(args.dependency or EXPECTED_DEPENDENCIES)
        if len(selected) != len(set(selected)):
            raise RegistryError("--dependency values must be unique")
        overrides = _archive_overrides(args.archive)
        if not set(overrides).issubset(selected):
            raise RegistryError("--archive dependency must also be selected")
        update(args.root, selected, overrides)
    except (RegistryError, OSError) as exc:
        print(f"telemetry upstream update failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
