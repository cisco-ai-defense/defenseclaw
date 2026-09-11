#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Build a development-only InjecAgent corpus for MCP YARA evaluation.

The adapter does not execute InjecAgent or a scanner. It projects the source
tool catalog into MCP ``tools/list`` documents and creates paired poisoned
variants by placing each source-labeled attacker instruction in the
description of the first tool referenced by that attack. Repeated enhanced
cases are deduplicated by their exact, whitespace-trimmed attacker instruction.
Cases from the same toolkit share a split group so a toolkit's benign source
descriptions cannot leak into a held-out poisoned-tool partition.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPO_ROOT / "outputs/benchmark-data/sources/injecagent/data"
DEFAULT_TOOLS = SOURCE_ROOT / "tools.json"
DEFAULT_ATTACKS = (
    SOURCE_ROOT / "test_cases_ds_enhanced.json",
    SOURCE_ROOT / "test_cases_dh_enhanced.json",
)
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"
DEFAULT_TARGET_PREFIX = "injecagent-yara-v1"
SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", type=Path, default=DEFAULT_TOOLS)
    parser.add_argument(
        "--attack-input",
        action="append",
        dest="attack_inputs",
        type=Path,
        help="enhanced InjecAgent JSON array; repeat for multiple files",
    )
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--data-dir",
        type=Path,
        required=True,
        help="benchmark --data-dir root beneath which MCP JSON artifacts are written",
    )
    parser.add_argument("--target-prefix", default=DEFAULT_TARGET_PREFIX)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    args = parser.parse_args()
    if not args.attack_inputs:
        args.attack_inputs = list(DEFAULT_ATTACKS)
    return args


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_json_array(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError(f"{path}: expected a JSON array of objects")
    return value


def clean_text(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def normalized_category(value: object) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(value).casefold()).strip("_")
    return normalized[:100] or "unknown"


def toolkit_split_group(toolkit: dict[str, Any]) -> str:
    toolkit_name = clean_text(toolkit.get("name_for_model"), field="toolkit name_for_model")
    return sha256_bytes(f"toolkit\x00{toolkit_name}".encode())[:24]


def validate_target_prefix(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("target prefix must be a relative path below data-dir")
    if any(not SAFE_SEGMENT.fullmatch(part) for part in path.parts):
        raise ValueError("target prefix contains an unsafe path segment")
    return path.as_posix()


def parameter_schema(parameters: object) -> dict[str, Any]:
    if parameters is None:
        parameters = []
    if not isinstance(parameters, list):
        raise ValueError("tool parameters must be an array")
    properties: dict[str, dict[str, Any]] = {}
    required: list[str] = []
    for parameter in parameters:
        if not isinstance(parameter, dict):
            raise ValueError("tool parameter must be an object")
        name = clean_text(parameter.get("name"), field="parameter name")
        if name in properties:
            raise ValueError(f"duplicate parameter name {name!r}")
        schema: dict[str, Any] = {"type": clean_text(parameter.get("type"), field=f"{name} type")}
        description = parameter.get("description")
        if isinstance(description, str) and description.strip():
            schema["description"] = description.strip()
        properties[name] = schema
        if parameter.get("required") is True:
            required.append(name)
    result: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        result["required"] = required
    return result


def source_tool_catalog(
    rows: Sequence[dict[str, Any]],
) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    catalog: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    seen: set[str] = set()
    for toolkit in rows:
        toolkit_name = clean_text(toolkit.get("name_for_model"), field="toolkit name_for_model")
        tools = toolkit.get("tools")
        if not isinstance(tools, list):
            raise ValueError(f"toolkit {toolkit_name!r} tools must be an array")
        for tool in tools:
            if not isinstance(tool, dict):
                raise ValueError(f"toolkit {toolkit_name!r} contains a non-object tool")
            source_name = clean_text(tool.get("name"), field=f"{toolkit_name} tool name")
            mcp_name = f"{toolkit_name}{source_name}"
            if not SAFE_SEGMENT.fullmatch(mcp_name):
                raise ValueError(f"unsafe projected MCP tool name {mcp_name!r}")
            if mcp_name in seen:
                raise ValueError(f"duplicate projected MCP tool name {mcp_name!r}")
            seen.add(mcp_name)
            catalog.append((mcp_name, toolkit, tool))
    return sorted(catalog, key=lambda item: item[0])


def mcp_tool_document(mcp_name: str, tool: dict[str, Any], *, instruction: str | None = None) -> dict[str, Any]:
    summary = clean_text(tool.get("summary"), field=f"{mcp_name} summary")
    description = summary if instruction is None else f"{summary}\n\n{instruction}"
    return {
        "tools": [
            {
                "name": mcp_name,
                "description": description,
                "inputSchema": parameter_schema(tool.get("parameters")),
            }
        ]
    }


def deduplicate_attacks(paths: Sequence[Path]) -> tuple[list[dict[str, Any]], int]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    source_rows = 0
    for path in sorted(paths, key=lambda item: (item.name, str(item))):
        for row in load_json_array(path):
            source_rows += 1
            instruction = clean_text(row.get("Attacker Instruction"), field="Attacker Instruction")
            grouped.setdefault(instruction, []).append(row)

    deduplicated: list[dict[str, Any]] = []
    for instruction, variants in sorted(grouped.items()):
        signatures: set[tuple[tuple[str, ...], str, str]] = set()
        for row in variants:
            tools = row.get("Attacker Tools")
            if not isinstance(tools, list) or not tools or any(not isinstance(item, str) or not item for item in tools):
                raise ValueError(f"attack instruction {instruction!r} has invalid Attacker Tools")
            signatures.add(
                (
                    tuple(tools),
                    clean_text(row.get("Attack Type"), field="Attack Type"),
                    clean_text(row.get("Expected Achievements"), field="Expected Achievements"),
                )
            )
        if len(signatures) != 1:
            raise ValueError(f"conflicting source labels for attacker instruction {instruction!r}")
        tools, attack_type, achievement = next(iter(signatures))
        deduplicated.append(
            {
                "instruction": instruction,
                "attacker_tools": tools,
                "attack_type": attack_type,
                "expected_achievement": achievement,
                "source_occurrences": len(variants),
            }
        )
    return deduplicated, source_rows


def case_source(revision: str, original_id: str) -> dict[str, str]:
    return {
        "dataset": "injecagent",
        "revision": revision,
        "original_id": original_id,
        "license": "MIT",
        "redistribution": "download-only",
    }


def build_corpus(
    tools_path: Path,
    attack_paths: Sequence[Path],
    *,
    revision: str,
    target_prefix: str = DEFAULT_TARGET_PREFIX,
) -> tuple[list[dict[str, Any]], dict[str, bytes], dict[str, Any]]:
    revision = clean_text(revision, field="revision")
    target_prefix = validate_target_prefix(target_prefix)
    catalog = source_tool_catalog(load_json_array(tools_path))
    by_name = {name: (toolkit, tool) for name, toolkit, tool in catalog}
    attacks, attack_source_rows = deduplicate_attacks(attack_paths)

    rows: list[dict[str, Any]] = []
    artifacts: dict[str, bytes] = {}

    for mcp_name, toolkit, tool in catalog:
        identity = sha256_bytes(f"benign\x00{mcp_name}".encode())
        target = f"{target_prefix}/benign-{identity[:24]}.json"
        artifacts[target] = canonical_json(mcp_tool_document(mcp_name, tool))
        rows.append(
            {
                "schema_version": "1",
                "id": f"injecagent-yara/benign/{identity[:24]}",
                "source": case_source(revision, f"tool:{mcp_name}"),
                "split": "development",
                "surface": "mcp",
                "payload": {"target": target},
                "truth": {
                    "source_truth": "benign",
                    "deterministic_truth": "benign",
                    "label_confidence": "high",
                    "label_source": "injecagent:source_tool_definition",
                    "applicability": "in_scope",
                    "expected_disposition": "allow",
                    "categories": ["mcp_tool_metadata", "source_tool_definition"],
                },
                "strata": {
                    "campaign": "benign_source_tool",
                    "domain": normalized_category(toolkit.get("category")),
                    "hard_negative": True,
                    "split_group": toolkit_split_group(toolkit),
                },
            }
        )

    for attack in attacks:
        instruction = str(attack["instruction"])
        attacker_tools = tuple(str(item) for item in attack["attacker_tools"])
        carrier = attacker_tools[0]
        if carrier not in by_name:
            raise ValueError(f"attacker instruction references unknown tool {carrier!r}")
        toolkit, tool = by_name[carrier]
        identity = sha256_bytes(f"malicious\x00{instruction}".encode())
        target = f"{target_prefix}/malicious-{identity[:24]}.json"
        artifacts[target] = canonical_json(mcp_tool_document(carrier, tool, instruction=instruction))
        attack_type = normalized_category(attack["attack_type"])
        rows.append(
            {
                "schema_version": "1",
                "id": f"injecagent-yara/malicious/{identity[:24]}",
                "source": case_source(revision, f"instruction:{sha256_bytes(instruction.encode())[:24]}"),
                "split": "development",
                "surface": "mcp",
                "payload": {"target": target},
                "truth": {
                    "source_truth": "malicious",
                    "deterministic_truth": "deterministic_malicious",
                    "label_confidence": "medium",
                    "label_source": "injecagent:attacker_instruction",
                    "applicability": "in_scope",
                    "expected_disposition": "detect_only",
                    "categories": [
                        "mcp_tool_metadata",
                        "synthetic_tool_poisoning",
                        "indirect_prompt_injection",
                        attack_type,
                    ],
                },
                "strata": {
                    "campaign": attack_type,
                    "domain": normalized_category(toolkit.get("category")),
                    "hard_negative": False,
                    "split_group": toolkit_split_group(toolkit),
                },
            }
        )

    rows.sort(key=lambda row: str(row["id"]))
    adapter_statistics = {
        "benign_tool_definition_count": len(catalog),
        "malicious_instruction_count": len(attacks),
        "attack_source_row_count": attack_source_rows,
        "duplicate_attack_rows_removed": attack_source_rows - len(attacks),
        "artifact_count": len(artifacts),
    }
    manifest = {
        "schema_version": "1",
        "datasets": ["injecagent"],
        "cases": len(rows),
        "counts": {"injecagent": len(rows)},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {"injecagent_yara": adapter_statistics},
    }
    return rows, artifacts, manifest


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - exercised by CLI environments without the dependency
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for row in rows:
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            raise ValueError(f"{row.get('id', '<unknown>')}:{location}: {errors[0].message}")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def write_outputs(
    rows: Sequence[dict[str, Any]],
    artifacts: dict[str, bytes],
    manifest: dict[str, Any],
    *,
    output: Path,
    data_dir: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    for target, data in sorted(artifacts.items()):
        atomic_write(data_dir / PurePosixPath(target), data)
    output_data = b"".join(canonical_json(row) for row in rows)
    atomic_write(output, output_data)
    complete_manifest = {
        **manifest,
        "output_sha256": sha256_bytes(output_data),
    }
    atomic_write(manifest_path, (json.dumps(complete_manifest, indent=2, sort_keys=True) + "\n").encode())
    return complete_manifest


def main() -> int:
    args = parse_args()
    rows, artifacts, manifest = build_corpus(
        args.tools,
        args.attack_inputs,
        revision=args.revision,
        target_prefix=args.target_prefix,
    )
    validate_cases(rows, args.schema)
    complete_manifest = write_outputs(
        rows,
        artifacts,
        manifest,
        output=args.output,
        data_dir=args.data_dir,
        manifest_path=args.manifest or args.output.with_suffix(".manifest.json"),
    )
    print(
        json.dumps(
            {
                "case_count": complete_manifest["cases"],
                **complete_manifest["adapter_statistics"]["injecagent_yara"],
                "output_sha256": complete_manifest["output_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
