#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize a pinned Cyber Task Horizons execution subset to case-v1.

The complete public corpus is roughly 18 GB. This adapter deliberately pins
two compact, successful InterCode-CTF archives with real linked Bash/Python
calls and tool results. A successful offensive task is trajectory context; it
does not make every dual-use command independently malicious.

Inspect result messages in this subset do not provide process exit codes.
Explicit tool errors therefore become ``failed`` while linked non-error
results remain ``unknown``. Result bodies, prompts, reasoning, targets,
attachments, flags, credentials, and model output are not projected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import tempfile
import zipfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = "1"
DATASET_ID = "lyptus-research/cyber-task-horizons-data"
SOURCE_URL = "https://github.com/lyptus-research/cyber-task-horizons-data"
SOURCE_REVISION = "178c0da1800f9c07311e1b8d6c61dd8104e7b4ae"
SOURCE_LICENSE = "CC-BY-4.0"
SOURCE_REDISTRIBUTION = "download-only"
MAX_EVENTS = 8
MAX_MESSAGES = 512
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_ARGUMENT_BYTES = 128 * 1024
MAX_VALUE_BYTES = 64 * 1024
MAX_ITEMS = 2048
MAX_DEPTH = 24
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"

ARCHIVES = {
    "intercode-gpt55.eval": {
        "bytes": 2_290_684,
        "sha256": "dc532b841589b197e40198909cf2b5698502c0bfcab4f8b59a64523c7991a86c",
        "eval_set": "eval-set-q2eavajb0blxpmc1",
        "model": "gpt-5.5-2026-04-23",
        "repository_path": "data/eval_logs/eval-set-q2eavajb0blxpmc1/full.eval",
    },
    "intercode-opus46.eval": {
        "bytes": 5_447_430,
        "sha256": "304c094a0e15eeec78401599e522b6e691f4b51ce97aaf1e4067536db9a1c122",
        "eval_set": "eval-set-x2n13zd6vulak29q",
        "model": "claude-opus-4-6",
        "repository_path": "data/eval_logs/eval-set-x2n13zd6vulak29q/full.eval",
    },
}

SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,239}$")
SAFE_TOOL = re.compile(r"^(bash|python)$")
SENSITIVE_ACTION = re.compile(r"(?i)(?:pico)?ctf\{|flag\{|private[ _-]?key")


class ProjectionError(ValueError):
    """A source record cannot be projected safely."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--revision", default=SOURCE_REVISION)
    parser.add_argument("--split", choices=("development",), default="development")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


def sha256_path(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError("duplicate_json_key")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise ProjectionError(f"non_finite_json:{value}")


def required_text(value: object, code: str, maximum: int = 240) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProjectionError(code)
    result = value.strip()
    if len(result.encode()) > maximum:
        raise ProjectionError(code)
    return result


def bounded(value: object, *, depth: int = 0) -> object:
    if depth > MAX_DEPTH:
        raise ProjectionError("arguments_too_deep")
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ProjectionError("non_finite_argument")
        return value
    if isinstance(value, str):
        if len(value.encode()) > MAX_VALUE_BYTES:
            raise ProjectionError("argument_value_too_large")
        return value
    if isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise ProjectionError("too_many_argument_items")
        return [bounded(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS or any(not isinstance(key, str) for key in value):
            raise ProjectionError("invalid_argument_object")
        return {key: bounded(item, depth=depth + 1) for key, item in value.items()}
    raise ProjectionError("unsupported_argument_type")


def safe_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    result: list[zipfile.ZipInfo] = []
    expanded = 0
    seen: set[str] = set()
    for info in archive.infolist():
        path = PurePosixPath(info.filename)
        if path.is_absolute() or ".." in path.parts or info.filename in seen:
            raise ValueError("unsafe or duplicate archive member")
        seen.add(info.filename)
        if info.is_dir() or not info.filename.startswith("samples/") or not info.filename.endswith(".json"):
            continue
        if info.file_size > MAX_MEMBER_BYTES:
            raise ValueError("sample member exceeds size bound")
        expanded += info.file_size
        if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
            raise ValueError("sample members exceed expansion bound")
        result.append(info)
    return sorted(result, key=lambda info: info.filename)


def load_sample(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> dict[str, Any]:
    try:
        value = json.loads(
            archive.read(info).decode("utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=reject_nonfinite,
        )
    except ProjectionError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ProjectionError("invalid_sample_json") from exc
    if not isinstance(value, dict):
        raise ProjectionError("invalid_sample")
    return value


def score_is_correct(sample: Mapping[str, Any]) -> bool:
    scores = sample.get("scores")
    if not isinstance(scores, dict) or not scores:
        raise ProjectionError("missing_scores")
    values: list[object] = []
    for score in scores.values():
        if not isinstance(score, dict):
            raise ProjectionError("invalid_score")
        values.append(score.get("value"))
    return any(value == "C" or value == 1 or value == 1.0 or value is True for value in values)


def sample_identity(sample: Mapping[str, Any], member: str) -> tuple[str, str, str]:
    task_id = required_text(sample.get("id"), "invalid_task_id")
    if not task_id.startswith("intercode-ctf_") or not SAFE_ID.fullmatch(task_id):
        raise ProjectionError("unsupported_task")
    metadata = sample.get("metadata")
    if not isinstance(metadata, dict):
        raise ProjectionError("invalid_metadata")
    category = required_text(metadata.get("category"), "invalid_category", 80)
    if category not in {"crypto", "general_skills", "pwn", "reverse"}:
        raise ProjectionError("unsupported_category")
    run_uuid = required_text(sample.get("uuid"), "invalid_run_uuid")
    if not SAFE_ID.fullmatch(run_uuid):
        raise ProjectionError("invalid_run_uuid")
    return task_id, category, digest(member, task_id, run_uuid)[:24]


def call_arguments(call: Mapping[str, Any]) -> tuple[str, dict[str, object], str]:
    tool = required_text(call.get("function"), "invalid_tool", 80)
    if call.get("function") != tool or not SAFE_TOOL.fullmatch(tool):
        raise ProjectionError("unsupported_tool")
    raw = call.get("arguments")
    if not isinstance(raw, dict):
        raise ProjectionError("invalid_arguments")
    projected = bounded(raw)
    if not isinstance(projected, dict) or len(canonical_json(projected).encode()) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("arguments_too_large")
    action_key = "cmd" if tool == "bash" else "code"
    action = projected.get(action_key)
    if not isinstance(action, str) or not action.strip() or len(action.encode()) > MAX_VALUE_BYTES:
        raise ProjectionError("missing_exact_action")
    if SENSITIVE_ACTION.search(action):
        raise ProjectionError("action_contains_target_or_sensitive_material")
    return tool, projected, action


def has_explicit_error(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        if len(value.encode()) > MAX_VALUE_BYTES:
            raise ProjectionError("invalid_result_error")
        return bool(value)
    if isinstance(value, dict):
        if set(value) != {"message", "type"}:
            raise ProjectionError("invalid_result_error")
        required_text(value.get("message"), "invalid_result_error", MAX_VALUE_BYTES)
        required_text(value.get("type"), "invalid_result_error", 240)
        return True
    raise ProjectionError("invalid_result_error")


def project_messages(sample: Mapping[str, Any]) -> tuple[list[dict[str, Any]], Counter[str], bool]:
    messages = sample.get("messages")
    if not isinstance(messages, list) or len(messages) > MAX_MESSAGES:
        raise ProjectionError("invalid_messages")
    pending: dict[str, Mapping[str, Any]] = {}
    consumed: set[str] = set()
    events: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    complete = True
    for message in messages:
        if not isinstance(message, dict):
            raise ProjectionError("invalid_message")
        calls = message.get("tool_calls")
        if calls is not None:
            if not isinstance(calls, list) or len(calls) > MAX_ITEMS:
                raise ProjectionError("invalid_tool_calls")
            for call in calls:
                if not isinstance(call, dict):
                    raise ProjectionError("invalid_tool_call")
                call_id = required_text(call.get("id"), "invalid_call_id", 512)
                if call_id in pending:
                    raise ProjectionError("duplicate_call_id")
                pending[call_id] = call
                counts["emitted_calls"] += 1
        if message.get("role") != "tool":
            continue
        call_id = required_text(message.get("tool_call_id"), "invalid_result_call_id", 512)
        if call_id in consumed or call_id not in pending:
            raise ProjectionError("unlinked_or_duplicate_result")
        consumed.add(call_id)
        call = pending[call_id]
        if message.get("function") != call.get("function"):
            raise ProjectionError("result_function_mismatch")
        result = message.get("content")
        if not isinstance(result, str) or len(result.encode()) > MAX_MEMBER_BYTES:
            raise ProjectionError("invalid_result_body")
        failed = has_explicit_error(message.get("error"))
        counts["linked_results"] += 1
        counts["result_bodies_excluded"] += 1
        counts["result_bytes_excluded"] += len(result.encode())
        if failed:
            counts["explicit_failed_results"] += 1
        else:
            counts["non_error_results_without_exit_code"] += 1
        try:
            tool, arguments, action = call_arguments(call)
        except ProjectionError as exc:
            counts[f"excluded_call:{exc.code}"] += 1
            complete = False
            continue
        event: dict[str, Any] = {
            "tool_name": tool,
            "args": arguments,
            "dialect": "posix" if tool == "bash" else "none",
            "outcome": "failed" if failed else "unknown",
        }
        if tool == "bash":
            event["command"] = action
        events.append(event)
        counts[f"selected_tool:{tool}"] += 1
    unexecuted = set(pending) - consumed
    if unexecuted:
        counts["unexecuted_emitted_calls"] += len(unexecuted)
        complete = False
    return events, counts, complete


def source(original_id: str) -> dict[str, str]:
    return {
        "dataset": DATASET_ID,
        "revision": SOURCE_REVISION,
        "original_id": original_id,
        "license": SOURCE_LICENSE,
        "redistribution": SOURCE_REDISTRIBUTION,
    }


def atomic_truth() -> dict[str, Any]:
    return {
        "source_truth": "unknown",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "high",
        "label_source": "source:linked_execution_atomic_truth_unavailable",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "exclusion_reason": "A correct offensive task score labels the trajectory, not an individual tool call.",
        "categories": ["cyber_task_horizons", "intercode_ctf", "executed_tool_call"],
    }


def stateful_truth(*, complete: bool, correct: bool) -> dict[str, Any]:
    if complete and correct:
        return {
            "source_truth": "malicious",
            "deterministic_truth": "contextual_or_dual_use",
            "label_confidence": "high",
            "label_source": "source:correct_complete_offensive_trajectory",
            "applicability": "in_scope",
            "expected_disposition": "detect_only",
            "categories": ["cyber_task_horizons", "intercode_ctf", "complete_successful_offensive_trajectory"],
        }
    return {
        "source_truth": "unknown",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "high",
        "label_source": "source:partial_or_unresolved_offensive_trajectory",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "exclusion_reason": (
            "The bounded window is incomplete, contains excluded sensitive output, or lacks a correct task score."
        ),
        "categories": ["cyber_task_horizons", "intercode_ctf", "partial_execution_window"],
    }


def action_payload(event: Mapping[str, Any]) -> dict[str, Any]:
    payload = {key: value for key, value in event.items() if key != "outcome"}
    return {"direction": "tool_call", **payload}


def normalize_directory(root: Path, revision: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if revision != SOURCE_REVISION:
        raise ValueError(f"revision must equal pinned revision {SOURCE_REVISION}")
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("input must be a directory")
    archive_paths: dict[str, Path] = {}
    source_files: dict[str, object] = {}
    for name, metadata in ARCHIVES.items():
        path = (resolved / name).resolve(strict=True)
        try:
            path.relative_to(resolved)
        except ValueError as exc:
            raise ValueError("archive path escapes input directory") from exc
        if path.stat().st_size != metadata["bytes"] or sha256_path(path) != metadata["sha256"]:
            raise ValueError(f"{name} does not match the pinned LFS object")
        archive_paths[name] = path
        source_files[name] = dict(metadata)

    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    models: Counter[str] = Counter()
    rejections: Counter[str] = Counter()
    task_ids: set[str] = set()
    seen_runs: set[tuple[str, str]] = set()
    for archive_name, path in archive_paths.items():
        archive_metadata = ARCHIVES[archive_name]
        with zipfile.ZipFile(path) as archive:
            members = safe_members(archive)
            counts["source_samples"] += len(members)
            for info in members:
                try:
                    sample = load_sample(archive, info)
                    task_id, category, trajectory = sample_identity(sample, info.filename)
                    correct = score_is_correct(sample)
                    events, event_counts, projection_complete = project_messages(sample)
                except ProjectionError as exc:
                    rejections[exc.code] += 1
                    continue
                identity = (archive_name, trajectory)
                if identity in seen_runs:
                    raise ValueError("duplicate run identity")
                seen_runs.add(identity)
                task_ids.add(task_id)
                counts.update(event_counts)
                categories[category] += 1
                models[str(archive_metadata["model"])] += 1
                counts["correct_trajectories" if correct else "incorrect_trajectories"] += 1
                if not events:
                    counts["trajectories_without_projected_events"] += 1
                    continue
                complete_bounded = projection_complete and len(events) <= MAX_EVENTS
                if complete_bounded and correct:
                    counts["complete_bounded_contextual_positives"] += 1
                elif len(events) > MAX_EVENTS:
                    counts["trajectories_exceeding_bound"] += 1
                for index, event in enumerate(events):
                    original = f"{archive_metadata['eval_set']}:{info.filename}#call-{index}"
                    strata = {
                        "platform": "linux",
                        "language": "english",
                        "ecosystem": "inspect_ai",
                        "campaign": "intercode_ctf",
                        "domain": category,
                        "document_type": str(event["tool_name"]),
                        "split_group": digest(SOURCE_REVISION, task_id)[:24],
                        "trajectory_id": trajectory,
                        "sequence_index": index,
                        "call_index": 0,
                    }
                    cases.append(
                        {
                            "schema_version": SCHEMA_VERSION,
                            "id": f"cyber-task-horizons/{trajectory}/action-{index:03d}",
                            "source": source(original),
                            "split": "development",
                            "surface": "action",
                            "payload": action_payload(event),
                            "truth": atomic_truth(),
                            "strata": strata,
                        }
                    )
                    counts["action_cases"] += 1
                    window = events[max(0, index - MAX_EVENTS + 1) : index + 1]
                    if len(window) < 2:
                        continue
                    window_events = [{**candidate, "offset_seconds": offset} for offset, candidate in enumerate(window)]
                    window_is_complete = complete_bounded and index == len(events) - 1 and len(window) == len(events)
                    cases.append(
                        {
                            "schema_version": SCHEMA_VERSION,
                            "id": f"cyber-task-horizons/{trajectory}/window-{index:03d}",
                            "source": source(f"{original}:window"),
                            "split": "development",
                            "surface": "stateful",
                            "payload": {"events": window_events},
                            "truth": stateful_truth(complete=window_is_complete, correct=correct),
                            "strata": strata,
                        }
                    )
                    counts["stateful_cases"] += 1

    cases.sort(key=lambda case: str(case["id"]))
    counts["cases"] = len(cases)
    counts["unique_tasks"] = len(task_ids)
    counts["benign_controls"] = 0
    counts["deterministic_malicious_proofs"] = 0
    statistics = dict(sorted(counts.items()))
    statistics.update({f"category:{key}": value for key, value in sorted(categories.items())})
    statistics.update({f"model:{key}": value for key, value in sorted(models.items())})
    statistics.update({f"rejection:{key}": value for key, value in sorted(rejections.items())})
    source_sha256 = digest(
        *(f"{name}:{metadata['sha256']}" for name, metadata in sorted(source_files.items()))
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET_ID],
        "cases": len(cases),
        "counts": {DATASET_ID: len(cases)},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {"cyber-task-horizons-v1": statistics},
        "source": {
            "dataset": DATASET_ID,
            "revision": SOURCE_REVISION,
            "license": SOURCE_LICENSE,
            "redistribution": SOURCE_REDISTRIBUTION,
            "path": "selected evaluation archives",
            "paths": sorted(source_files),
            "bytes": sum(int(metadata["bytes"]) for metadata in source_files.values()),
            "files": len(source_files),
            "rows": counts["source_samples"],
            "sha256": source_sha256,
            "source_url": SOURCE_URL,
        },
    }
    return cases, manifest


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path) -> None:
    import jsonschema

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for row in rows:
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            raise ValueError(f"{row.get('id', '<unknown>')}:{location}: {errors[0].message}")


def write_outputs(cases: Sequence[dict[str, Any]], manifest: dict[str, Any], output: Path, manifest_path: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = "".join(canonical_json(case) + "\n" for case in cases)
    manifest["output_sha256"] = hashlib.sha256(serialized.encode()).hexdigest()
    for path, content in ((output, serialized), (manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
            handle.write(content)
            temporary = Path(handle.name)
        os.replace(temporary, path)


def main() -> int:
    args = parse_args()
    cases, manifest = normalize_directory(args.input_dir, args.revision)
    validate_cases(cases, args.schema)
    write_outputs(cases, manifest, args.output, args.manifest or args.output.with_suffix(".manifest.json"))
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
