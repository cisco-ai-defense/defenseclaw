#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize the pinned TraceSafe paired trajectories without label leakage.

Only agent-issued tool names and a value-free projection of structured
arguments enter detector payloads. User prompts, assistant prose/reasoning,
tool results, tool definitions, mutation rationales, diffs, and injected
values are never projected. A mutated case is deterministic only when the
original/new pair proves a mutation that remains visible after this projection.
All other source attacks are contextual, proof-required discovery cases.

Rows sharing the exact canonical original trace share one split group. The
adapter emits only the ``smoke`` staging split; benchmark_partition.py owns the
development/validation/sealed-test assignment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
ADAPTER = "tracesafe-paired-value-free-v1"
DATASET = "CyCraftAI/TraceSafe"
SOURCE_URL = "https://huggingface.co/datasets/CyCraftAI/TraceSafe"
SOURCE_REVISION = "b8d546242a7182d2f5a97f5ff88cecca63d8e719"
SOURCE_LICENSE = "Apache-2.0"
REDISTRIBUTION = "download-only"
PRE_PARTITION_SPLIT = "smoke"
GROUPING_STRATEGY = "tracesafe-exact-original-trace-pair-v1"
PARTITION_AUTHORITY = "benchmarks/scripts/benchmark_partition.py"

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"
SOURCE_FILES = (
    "golden_0_benign.jsonl",
    "golden_1_PromptInjectionIn.jsonl",
    "golden_2_PromptInjectionOut.jsonl",
    "golden_3_UserInfoLeak.jsonl",
    "golden_4_ApiKeyLeak.jsonl",
    "golden_5_DataLeak.jsonl",
    "golden_6_AmbiguousArg.jsonl",
    "golden_7_HallucinatedTool.jsonl",
    "golden_8_HallucinatedArgValue.jsonl",
    "golden_9_RedundantArg.jsonl",
    "golden_10_MissingTypeHint.jsonl",
    "golden_11_VersionConflict.jsonl",
    "golden_12_DescriptionMismatch.jsonl",
)
MUTATION_FILES = {name: index for index, name in enumerate(SOURCE_FILES)}
MAX_SOURCE_LINE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 256 * 1024 * 1024
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_VALUE_BYTES = 1024 * 1024
MAX_ITEMS = 4096
MAX_DEPTH = 32
MAX_CALLS = 1801
MAX_EVENTS = 64
HEX_24 = re.compile(r"^[0-9a-f]{24}$")
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_TOOL = re.compile(r"^[^\x00-\x1f\x7f]{1,240}$")
EXCLUDED_PAYLOAD_KEYS = frozenset({"content", "difference", "message", "prompt", "reasoning", "result", "tool_result"})
MUTATION_SLUGS = {
    "benign": "benign",
    "PromptInjectionIn": "prompt-injection-in",
    "PromptInjectionOut": "prompt-injection-out",
    "UserInfoLeak": "user-info-leak",
    "ApiKeyLeak": "api-key-leak",
    "DataLeak": "data-leak",
    "AmbiguousArg": "ambiguous-argument",
    "HallucinatedTool": "hallucinated-tool",
    "HallucinatedArgValue": "hallucinated-argument-value",
    "RedundantArg": "redundant-argument",
    "MissingTypeHint": "missing-type-hint",
    "VersionConflict": "version-conflict",
    "DescriptionMismatch": "description-mismatch",
}


class ProjectionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict[str, Any]


@dataclass(frozen=True)
class Pair:
    source_id: str
    category: str
    domain: str
    model: str
    pair_digest: str
    original: tuple[ToolCall, ...]
    mutated: tuple[ToolCall, ...]
    visible_mutations: frozenset[int]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--revision", default=SOURCE_REVISION)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--group-manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


def sha256_file(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def git_blob_sha1(path: Path) -> str:
    completed = subprocess.run(
        ["git", "hash-object", "--", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    value = completed.stdout.strip()
    if not HEX_40.fullmatch(value):
        raise ValueError(f"invalid Git blob identity for {path.name}")
    return value


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError("duplicate_json_key")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise ProjectionError(f"non_finite_json:{value}")


def bounded(value: object, depth: int = 0) -> object:
    if depth > MAX_DEPTH:
        raise ProjectionError("maximum_json_depth_exceeded")
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ProjectionError("non_finite_number")
        return value
    if isinstance(value, str):
        if "\x00" in value or len(value.encode()) > MAX_VALUE_BYTES:
            raise ProjectionError("invalid_string")
        return value
    if isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise ProjectionError("too_many_array_items")
        return [bounded(item, depth + 1) for item in value]
    if isinstance(value, Mapping):
        if len(value) > MAX_ITEMS or any(not isinstance(key, str) or "\x00" in key for key in value):
            raise ProjectionError("invalid_object")
        return {key: bounded(item, depth + 1) for key, item in value.items()}
    raise ProjectionError("unsupported_json_value")


def value_free(value: object, depth: int = 0) -> object:
    """Retain argument names/container shape/types, never scalar values."""
    if depth > MAX_DEPTH:
        raise ProjectionError("maximum_json_depth_exceeded")
    if value is None:
        return "<redacted:null>"
    if type(value) is bool:
        return "<redacted:boolean>"
    if type(value) is int:
        return "<redacted:integer>"
    if type(value) is float:
        if not math.isfinite(value):
            raise ProjectionError("non_finite_number")
        return "<redacted:number>"
    if isinstance(value, str):
        if "\x00" in value or len(value.encode()) > MAX_VALUE_BYTES:
            raise ProjectionError("invalid_string")
        return "<redacted:string>"
    if isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise ProjectionError("too_many_array_items")
        return [value_free(item, depth + 1) for item in value]
    if isinstance(value, Mapping):
        if len(value) > MAX_ITEMS or any(not isinstance(key, str) or "\x00" in key for key in value):
            raise ProjectionError("invalid_object")
        return {key: value_free(item, depth + 1) for key, item in sorted(value.items())}
    raise ProjectionError("unsupported_json_value")


def metadata_path(root: Path, path: Path) -> Path:
    relative = path.resolve().relative_to(root.resolve())
    return root / ".cache/huggingface/download" / relative.parent / f"{relative.name}.metadata"


def verify_pinned_source(root: Path, revision: str) -> list[Path]:
    root = root.resolve(strict=True)
    if revision != SOURCE_REVISION:
        raise ValueError("TraceSafe revision differs from datasets.lock.json")
    readme = root / "README.md"
    required = [readme, *(root / name for name in SOURCE_FILES)]
    for path in required:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_SOURCE_FILE_BYTES:
            raise ValueError(f"missing or invalid pinned TraceSafe file: {path.name}")
        try:
            path.resolve(strict=True).relative_to(root)
        except ValueError as exc:
            raise ValueError("TraceSafe source path escapes source root") from exc
        metadata = metadata_path(root, path)
        if not metadata.is_file() or metadata.is_symlink():
            raise ValueError(f"missing Hugging Face metadata for {path.name}")
        lines = metadata.read_text(encoding="utf-8").splitlines()
        if (
            len(lines) < 2
            or lines[0] != SOURCE_REVISION
            or not (HEX_40.fullmatch(lines[1]) or HEX_64.fullmatch(lines[1]))
        ):
            raise ValueError(f"invalid pinned identity for {path.name}")
        actual = git_blob_sha1(path) if len(lines[1]) == 40 else sha256_file(path)
        if actual != lines[1]:
            raise ValueError(f"Hugging Face etag mismatch for {path.name}")
    text = readme.read_text(encoding="utf-8")
    if not re.search(r"(?mi)^license:\s*apache-2\.0\s*$", text):
        raise ValueError("TraceSafe README does not declare Apache-2.0")
    return [root / name for name in SOURCE_FILES]


def jsonl_rows(path: Path) -> Iterable[tuple[int, dict[str, Any]]]:
    with path.open("rb") as handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            if len(raw) > MAX_SOURCE_LINE_BYTES:
                raise ValueError(f"{path.name}:{line_number}: source line too large")
            try:
                value = json.loads(raw, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
                value = bounded(value)
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ProjectionError) as exc:
                raise ValueError(f"{path.name}:{line_number}: invalid source JSON") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path.name}:{line_number}: expected object")
            yield line_number, value


def trace_calls(trace: object) -> tuple[ToolCall, ...]:
    if not isinstance(trace, Mapping):
        raise ProjectionError("invalid_trace")
    messages = trace.get("trace")
    if not isinstance(messages, list):
        raise ProjectionError("invalid_trace_messages")
    calls: list[ToolCall] = []
    for message in messages:
        if not isinstance(message, Mapping) or message.get("role") != "agent":
            continue
        content = message.get("content")
        if not isinstance(content, Mapping):
            continue  # assistant prose is intentionally excluded
        name, arguments = content.get("name"), content.get("arguments")
        if not isinstance(name, str) or not SAFE_TOOL.fullmatch(name) or not isinstance(arguments, dict):
            raise ProjectionError("invalid_agent_tool_call")
        if len(canonical_bytes(arguments)) > MAX_ARGUMENT_BYTES:
            raise ProjectionError("arguments_too_large")
        calls.append(ToolCall(name=name, args=value_free(arguments)))
        if len(calls) > MAX_CALLS:
            raise ProjectionError("too_many_tool_calls")
    if not calls:
        raise ProjectionError("no_tool_calls")
    return tuple(calls)


def project_pair(row: Mapping[str, Any], source_id: str, expected_category: str) -> Pair:
    required = {"mutation_category", "original_trace", "new_trace", "difference", "mutation_metadata", "golden_meta"}
    if set(row) != required:
        raise ProjectionError("invalid_row_keys")
    meta = row["golden_meta"]
    if not isinstance(meta, Mapping) or meta.get("category") != expected_category:
        raise ProjectionError("category_mismatch")
    pure = expected_category == "benign"
    if meta.get("type") != ("pure_benign" if pure else "attacked"):
        raise ProjectionError("invalid_golden_type")
    original_trace, mutated_trace = row["original_trace"], row["new_trace"]
    if pure and (row["difference"] != {} or original_trace != mutated_trace):
        raise ProjectionError("invalid_benign_pair")
    if not pure and (row["difference"] == {} or original_trace == mutated_trace):
        raise ProjectionError("invalid_attacked_pair")
    original, mutated = trace_calls(original_trace), trace_calls(mutated_trace)
    if len(original) != len(mutated):
        raise ProjectionError("tool_call_count_changed")
    visible = frozenset(
        index
        for index, (before, after) in enumerate(zip(original, mutated))
        if (before.name, before.args) != (after.name, after.args)
    )
    trace_map = mutated_trace if isinstance(mutated_trace, Mapping) else {}
    domain = trace_map.get("domain", "unknown")
    model = meta.get("source_model", trace_map.get("agent_model", "unknown"))
    if (
        not isinstance(domain, str)
        or not domain
        or len(domain) > 160
        or not isinstance(model, str)
        or not model
        or len(model) > 80
    ):
        raise ProjectionError("invalid_strata")
    pair_digest = hashlib.sha256(canonical_bytes(original_trace)).hexdigest()
    return Pair(source_id, expected_category, domain, model, pair_digest, original, mutated, visible)


def event(call: ToolCall, offset: int) -> dict[str, Any]:
    return {
        "tool_name": call.name,
        "args": call.args,
        "dialect": "none",
        "outcome": "unknown",
        "offset_seconds": offset,
    }


def truth(pair: Pair, *, visible: bool) -> dict[str, Any]:
    if pair.category == "benign":
        return {
            "source_truth": "benign",
            "deterministic_truth": "benign",
            "label_confidence": "high",
            "label_source": "source:tracesafe_pure_benign_pair",
            "applicability": "in_scope",
            "expected_disposition": "allow",
            "expected_profile_actions": {"default": "allow", "permissive": "allow", "strict": "allow"},
            "categories": ["paired-benign", "value-free-tool-call"],
        }
    category = MUTATION_SLUGS[pair.category]
    if visible:
        return {
            "source_truth": "malicious",
            "deterministic_truth": "deterministic_malicious",
            "label_confidence": "high",
            "label_source": "source:tracesafe_exact_request_mutation",
            "applicability": "in_scope",
            "expected_disposition": "detect_only",
            "expected_profile_actions": {"default": "alert", "permissive": "allow", "strict": "alert"},
            "categories": [category, "exact-request-visible-mutation", "value-free-tool-call"],
        }
    return {
        "source_truth": "malicious",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "medium",
        "label_source": "source:tracesafe_contextual_mutation",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "categories": [category, "proof-required-contextual-mutation", "value-free-tool-call"],
        "exclusion_reason": (
            "The source mutation is not observable in the value-free tool request; prompt, schema, reasoning, "
            "tool-result, or scalar-value evidence is excluded from detector input."
        ),
    }


def make_case(pair: Pair, kind: str, ordinal: int, calls: Sequence[ToolCall], visible: bool) -> dict[str, Any]:
    group = pair.pair_digest[:24]
    payload: dict[str, Any]
    surface: str
    row_truth = truth(pair, visible=visible)
    if kind == "action":
        call = calls[0]
        payload = {"direction": "tool_call", "tool_name": call.name, "args": call.args, "dialect": "none"}
        surface = "action"
    else:
        payload = {"direction": "tool_call", "events": [event(call, index) for index, call in enumerate(calls)]}
        surface = "stateful"
        row_truth["stateful_lens"] = "bounded_intent"
    payload_key = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    return {
        "schema_version": SCHEMA_VERSION,
        "id": f"tracesafe/{digest(pair.source_id, kind, str(ordinal), payload_key)[:32]}",
        "source": {
            "dataset": DATASET,
            "revision": SOURCE_REVISION,
            "original_id": f"{pair.source_id}:{kind}:{ordinal}",
            "license": SOURCE_LICENSE,
            "redistribution": REDISTRIBUTION,
        },
        "split": PRE_PARTITION_SPLIT,
        "surface": surface,
        "payload": payload,
        "truth": row_truth,
        "strata": {
            "platform": "bfcl",
            "provider": pair.model,
            "domain": pair.domain,
            "campaign": MUTATION_SLUGS[pair.category],
            "hard_negative": pair.category == "benign",
            "split_group": group,
            "trajectory_id": pair.pair_digest,
            "sequence_index": ordinal,
            "call_index": ordinal,
        },
    }


def pair_cases(pair: Pair) -> list[dict[str, Any]]:
    rows = [
        make_case(pair, "action", index, [call], index in pair.visible_mutations)
        for index, call in enumerate(pair.mutated)
    ]
    if len(pair.mutated) >= 2:
        for start in range(0, len(pair.mutated), MAX_EVENTS):
            window = pair.mutated[start : start + MAX_EVENTS]
            if len(window) >= 2:
                visible = any(index in pair.visible_mutations for index in range(start, start + len(window)))
                rows.append(make_case(pair, "stateful", start, window, visible))
    return rows


def build_corpus(
    source_rows: Iterable[tuple[str, int, Mapping[str, Any]]], revision: str
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    if revision != SOURCE_REVISION:
        raise ValueError("TraceSafe revision differs from datasets.lock.json")
    pairs: list[Pair] = []
    stats: Counter[str] = Counter()
    seen_source_ids: set[str] = set()
    for filename, line_number, row in source_rows:
        if filename not in MUTATION_FILES:
            raise ValueError("unknown TraceSafe source file")
        expected = "benign" if filename == SOURCE_FILES[0] else filename.split("_", 2)[2].removesuffix(".jsonl")
        source_id = f"{filename}:{line_number}"
        if source_id in seen_source_ids:
            raise ValueError("duplicate TraceSafe source identity")
        seen_source_ids.add(source_id)
        stats["source_rows"] += 1
        try:
            pair = project_pair(row, source_id, expected)
        except ProjectionError as exc:
            stats[f"excluded_{exc.code}"] += 1
            continue
        pairs.append(pair)
        stats["pairs_emitted"] += 1
        stats["request_visible_pairs"] += bool(pair.visible_mutations)
        stats["contextual_pairs"] += not bool(pair.visible_mutations) and pair.category != "benign"
        stats["benign_pairs"] += pair.category == "benign"
    if not seen_source_ids:
        raise ValueError("no TraceSafe source rows loaded")
    rows = [case for pair in pairs for case in pair_cases(pair)]
    rows.sort(key=lambda value: value["id"])
    if len({row["id"] for row in rows}) != len(rows):
        raise ValueError("generated duplicate TraceSafe case IDs")
    stats["action_cases"] = sum(row["surface"] == "action" for row in rows)
    stats["stateful_cases"] = sum(row["surface"] == "stateful" for row in rows)
    stats["deterministic_malicious_cases"] = sum(
        row["truth"]["deterministic_truth"] == "deterministic_malicious" for row in rows
    )
    stats["contextual_cases"] = sum(row["truth"]["deterministic_truth"] == "contextual_or_dual_use" for row in rows)
    stats["benign_cases"] = sum(row["truth"]["deterministic_truth"] == "benign" for row in rows)
    output = b"".join(canonical_bytes(row) for row in rows)
    groups: dict[str, dict[str, int]] = defaultdict(
        lambda: {"pairs": 0, "cases": 0, "action_cases": 0, "stateful_cases": 0}
    )
    pair_groups = Counter(pair.pair_digest[:24] for pair in pairs)
    for group, count in pair_groups.items():
        groups[group]["pairs"] = count
    for row in rows:
        group = row["strata"]["split_group"]
        groups[group]["cases"] += 1
        groups[group][f"{row['surface']}_cases"] += 1
    group_rows = [{"group": group, **groups[group]} for group in sorted(groups)]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET],
        "cases": len(rows),
        "counts": {DATASET: len(rows)},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {ADAPTER: dict(sorted(stats.items()))},
        "output_sha256": hashlib.sha256(output).hexdigest(),
    }
    group_manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "tracesafe-trajectory-group-index-v1",
        "grouping_strategy": GROUPING_STRATEGY,
        "partition_authority": PARTITION_AUTHORITY,
        "group_count": len(group_rows),
        "pair_count": len(pairs),
        "case_count": len(rows),
        "groups": group_rows,
        "corpus_sha256": manifest["output_sha256"],
    }
    return rows, manifest, group_manifest


def validate_cases(rows: Sequence[dict[str, Any]], schema_path: Path = DEFAULT_SCHEMA) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError("jsonschema is required to validate TraceSafe cases") from exc
    validator = jsonschema.Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))
    group_splits: dict[str, str] = {}
    for row in rows:
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            raise ValueError(f"case schema validation failed at {location or '<root>'}: {errors[0].message}")
        if row["split"] != PRE_PARTITION_SPLIT:
            raise ValueError("TraceSafe normalization must remain in smoke staging split")
        group = row["strata"]["split_group"]
        if group in group_splits and group_splits[group] != row["split"]:
            raise ValueError("TraceSafe pair group crosses benchmark splits")
        group_splits[group] = row["split"]
        if any(key in row["payload"] for key in EXCLUDED_PAYLOAD_KEYS):
            raise ValueError("excluded source field entered payload")
        projected = row["payload"].get("events") or [row["payload"]]
        for item in projected:
            assert_value_free(item.get("args"))


def assert_value_free(value: object) -> None:
    if isinstance(value, Mapping):
        for child in value.values():
            assert_value_free(child)
        return
    if isinstance(value, list):
        for child in value:
            assert_value_free(child)
        return
    if not isinstance(value, str) or not re.fullmatch(r"<redacted:(?:null|boolean|integer|number|string)>", value):
        raise ValueError("TraceSafe payload is not value-free")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.replace(name, path)
    except BaseException:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
        raise


def main() -> None:
    args = parse_args()
    paths = verify_pinned_source(args.source_root, args.revision)
    rows, manifest, group_manifest = build_corpus(
        ((path.name, line, row) for path in paths for line, row in jsonl_rows(path)), args.revision
    )
    validate_cases(rows, args.schema)
    output = b"".join(canonical_bytes(row) for row in rows)
    if hashlib.sha256(output).hexdigest() != manifest["output_sha256"]:
        raise ValueError("TraceSafe manifest digest mismatch")
    atomic_write(args.output, output)
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    group_path = args.group_manifest or args.output.with_suffix(".groups.json")
    atomic_write(manifest_path, canonical_bytes(manifest))
    atomic_write(group_path, canonical_bytes(group_manifest))
    print(
        json.dumps(
            {"cases": len(rows), "groups": group_manifest["group_count"], "output_sha256": manifest["output_sha256"]},
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
