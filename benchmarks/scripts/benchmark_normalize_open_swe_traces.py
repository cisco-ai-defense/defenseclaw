#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize verified Open-SWE-Traces v1.2 Bash calls as benign actions.

Only trajectories with explicit source success and a documented repository
language are authoritative benign hard negatives. Prompts, reasoning, tool
results, patches, and other message content are deliberately excluded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

MAX_ARGUMENT_BYTES = 65_536
RESOLVED_SUCCESS = 1
RESOLVED_FAILED = 0
RESOLVED_UNKNOWN = -1
SUPPORTED_LANGUAGES = frozenset({
    "c",
    "cpp",
    "go",
    "java",
    "javascript",
    "php",
    "python",
    "rust",
    "typescript",
})


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def normalize(rows: Iterable[dict[str, Any]], revision: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    source_rows = source_calls = 0
    for row in rows:
        source_rows += 1
        trajectory = row.get("trajectory_id")
        messages = row.get("messages")
        if not isinstance(trajectory, str) or not trajectory or not isinstance(messages, list):
            skipped["invalid_row"] += 1
            continue
        source_calls += sum(
            len(message["tool_calls"])
            for message in messages
            if isinstance(message, dict) and isinstance(message.get("tool_calls"), list)
        )
        group = digest(f"{revision}\0{trajectory}")[:24]
        if "resolved" not in row or row["resolved"] is None:
            skipped["missing_resolved_status"] += 1
            continue
        resolved = row["resolved"]
        if type(resolved) is not int:
            skipped["ambiguous_resolved_status"] += 1
            continue
        if resolved == RESOLVED_FAILED:
            skipped["failed_trajectory"] += 1
            continue
        if resolved == RESOLVED_UNKNOWN:
            skipped["unresolved_trajectory"] += 1
            continue
        if resolved != RESOLVED_SUCCESS:
            skipped["unsupported_resolved_status"] += 1
            continue
        if "language" not in row or row["language"] is None:
            skipped["missing_language"] += 1
            continue
        language = row["language"]
        if not isinstance(language, str) or language not in SUPPORTED_LANGUAGES:
            skipped["unsupported_language"] += 1
            continue
        sequence = 0
        for message in messages:
            if not isinstance(message, dict) or not isinstance(message.get("tool_calls"), list):
                continue
            for call in message["tool_calls"]:
                call_index = sequence
                sequence += 1
                function = call.get("function") if isinstance(call, dict) else None
                if not isinstance(function, dict) or function.get("name") != "bash":
                    skipped["non_bash_call"] += 1
                    continue
                arguments = function.get("arguments")
                if isinstance(arguments, str):
                    try:
                        arguments = json.loads(arguments)
                    except json.JSONDecodeError:
                        skipped["invalid_arguments"] += 1
                        continue
                if (
                    not isinstance(arguments, dict)
                    or set(arguments) != {"command"}
                    or not isinstance(arguments["command"], str)
                ):
                    skipped["invalid_arguments"] += 1
                    continue
                if len(canonical_json(arguments).encode()) > MAX_ARGUMENT_BYTES:
                    skipped["oversized_arguments"] += 1
                    continue
                identity = digest(f"{revision}\0{trajectory}\0{call_index}")
                cases.append({
                    "schema_version": "1", "id": f"open-swe-traces-v1.2/{identity[:24]}",
                    "source": {
                        "dataset": "open-swe-traces-v1.2", "revision": revision,
                        "original_id": f"trajectory:{trajectory}#call-{call_index}",
                        "license": "CC-BY-4.0", "redistribution": "download-only",
                    },
                    "split": "development", "surface": "action",
                    "payload": {"tool_name": "Bash", "args": arguments, "dialect": "posix"},
                    "truth": {
                        "source_truth": "benign",
                        "deterministic_truth": "benign",
                        "label_confidence": "medium",
                        "label_source": "source:resolved_sandboxed_software_engineering_trajectory",
                        "applicability": "in_scope",
                        "expected_disposition": "allow",
                        "categories": ["coding_agent_trace", "benign_hard_negative", "sandboxed_repository_task"],
                    },
                    "strata": {
                        "domain": "shell_tool_call", "hard_negative": True, "split_group": group,
                        "trajectory_id": group, "sequence_index": call_index, "call_index": call_index,
                        "language": language,
                    },
                })
    cases.sort(key=lambda case: str(case["id"]))
    return cases, {
        "schema_version": "1", "source_id": "open-swe-traces-v1.2", "source_revision": revision,
        "source_license": "CC-BY-4.0", "source_rows": source_rows, "source_tool_calls": source_calls,
        "cases": len(cases), "row_count": len(cases), "skipped": dict(sorted(skipped.items())),
        "required_resolved_status": RESOLVED_SUCCESS,
        "supported_languages": sorted(SUPPORTED_LANGUAGES),
        "normalization": (
            "explicitly resolved trajectories in documented repository languages; exact Bash tool calls and decoded "
            "command argument only; prompts, reasoning, observations, patches, and tool output excluded"
        ),
        "label_limitation": (
            "Source success is execution-backed trajectory-level benign truth, not proof that every individual action "
            "is safe in every deployment; deployment-specific protected-resource policy still applies."
        ),
    }


def parquet_rows(paths: Iterable[Path]) -> Iterable[dict[str, Any]]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError("pyarrow is required to read Open-SWE-Traces Parquet") from exc
    required = {"trajectory_id", "language", "resolved", "messages"}
    for path in paths:
        source = parquet.ParquetFile(path)
        missing = sorted(required - set(source.schema_arrow.names))
        if missing:
            raise ValueError(f"{path} is missing columns: {', '.join(missing)}")
        for batch in source.iter_batches(batch_size=16, columns=sorted(required)):
            yield from batch.to_pylist()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=Path("benchmarks/schema/case-v1.schema.json"))
    return parser.parse_args()


def main() -> int:
    import jsonschema
    args = parse_args()
    cases, manifest = normalize(parquet_rows(args.input), args.revision)
    validator = jsonschema.Draft202012Validator(json.loads(args.schema.read_text()))
    for case in cases:
        errors = list(validator.iter_errors(case))
        if errors:
            raise ValueError(f"{case['id']}: {errors[0].message}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    output = "".join(canonical_json(case) + "\n" for case in cases)
    args.output.write_text(output)
    manifest["output_sha256"] = hashlib.sha256(output.encode()).hexdigest()
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
