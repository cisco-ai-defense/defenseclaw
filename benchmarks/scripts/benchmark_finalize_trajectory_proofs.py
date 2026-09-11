#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Finalize collected trajectory proofs into strict scorer overrides."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

if __package__:
    from . import benchmark_label_trajectory_bedrock as labeler
    from . import benchmark_score_trajectories as scorer
else:
    import benchmark_label_trajectory_bedrock as labeler
    import benchmark_score_trajectories as scorer

SCHEMA_VERSION = "1"
SUMMARY_KIND = "trajectory-proof-finalization-summary-v1"
CONFLICT_KIND = "trajectory-proof-conflict-v1"

_URL = re.compile(r"\b(?:https?|s3|gs|az|azure|file)://[^\s\"'`<>{}\[\]]+", re.IGNORECASE)
_ARN = re.compile(r"\barn:[A-Za-z0-9_./:=+\-@]+")
_AZURE_RESOURCE = re.compile(r"/subscriptions/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+){2,}", re.IGNORECASE)
_GCP_RESOURCE = re.compile(r"\bprojects/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+){1,}")
_UNIX_PATH = re.compile(r"(?<![A-Za-z0-9])(?:/|\.{1,2}/)[A-Za-z0-9._~@%+=:,/\-]+")
_WINDOWS_PATH = re.compile(r"\b[A-Za-z]:\\[^\s\"'`<>|]+")
_ARTIFACT_NAME = re.compile(
    r"\b[A-Za-z0-9_.-]+\.(?:bat|bin|cmd|dll|exe|gz|jar|js|ps1|py|sh|so|tar|tgz|zip)\b",
    re.IGNORECASE,
)
_STABLE_TOKEN = re.compile(r"^[A-Za-z0-9_./:=+@%\-]+$")
_DATABASE_KEY = re.compile(r"(?:^|_)(?:database|db|schema|table)(?:$|_)")
_PATH_KEY = re.compile(r"(?:^|_)(?:file|filename|path|filepath|source|target)(?:$|_)")
_RESOURCE_KEY = re.compile(
    r"(?:^|_)(?:account|artifact|bucket|cluster|credential|image|object|project|resource|secret|subscription|workspace)(?:_?id|_?ref|_?name)?(?:$|_)"
)
_ARTIFACT_KEY = re.compile(r"(?:^|_)(?:artifact|binary|executable|image|object|payload)(?:$|_)")
_SECRET_KEY = re.compile(r"(?:^|_)(?:api_?key|auth|credential|password|secret|token)(?:$|_)")
_CONTINUITY_KINDS = {
    "exact_file_ref": {"artifact", "path"},
    "exact_value_ref": {"secret_literal"},
    "exact_artifact_ref": {"artifact", "path", "resource_id", "url"},
    "exact_credential_ref": {"path", "resource_id", "secret_literal"},
    "exact_payload_ref": {"artifact", "path", "resource_id"},
    "same_database_scope": {"database", "resource_id", "url"},
    "same_cloud_scope": {"resource_id", "url"},
    "literal_atomic": set(),
}

_PREPARE_KEYS = {
    "schema_version",
    "workflow",
    "prompt_version",
    "model_id",
    "split",
    "source_sha256",
    "requests_sha256",
    "index_sha256",
    "trajectory_count",
    "event_count",
    "record_count",
    "one_trajectory_per_record",
    "max_trajectory_events",
    "max_serialized_chars",
    "max_completion_tokens",
    "temperature",
    "top_p",
    "reasoning_effort",
    "system_prompt_sha256",
    "trajectory_set_sha256",
    "skipped",
    "token_usage_estimate",
}
_COLLECT_KEYS = {
    "schema_version",
    "workflow",
    "prompt_version",
    "model_id",
    "job_arn",
    "requests_sha256",
    "index_sha256",
    "labels_sha256",
    "label_count",
    "review_required_count",
    "errors",
    "token_usage",
}
_COLLECTED_LABEL_KEYS = {
    "schema_version",
    "id",
    "trajectory_record_id",
    "prompt_version",
    "model_id",
    "input_sha256",
    "trajectory_input_sha256",
    "sequence_index",
    "call_index",
    "label",
    "review_required",
}
_EVENT_LABEL_KEYS = {
    "event_index",
    "verdict",
    "disposition",
    "confidence",
    "facts",
    "completed_proof_ids",
    "predecessor_indexes",
    "reason_code",
    "completed_proofs",
}
_FACT_KEYS = {
    "operation",
    "resource",
    "scope",
    "sensitivity",
    "destination_trust",
    "control_flow",
    "result",
    "identity_refs",
}
_PROOF_KEYS = {
    "proof_id",
    "proof_type",
    "event_indexes",
    "predecessor_indexes",
    "terminal_event_index",
    "identity_continuity",
    "identity_ref",
    "reason_code",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--labeling-input", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--labels-manifest", type=Path, required=True)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--prepare-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--conflicts", type=Path)
    return parser.parse_args()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{path}: invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def _load_jsonl(path: Path, *, allow_empty: bool = False) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line, object_pairs_hook=_strict_object)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(f"{path}: invalid JSON on line {line_number}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}: JSONL row {line_number} is not an object")
            rows.append(value)
    if not rows and not allow_empty:
        raise ValueError(f"{path}: no rows")
    return rows


def _required_int(value: Any, field: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{field} must be an integer >= {minimum}")
    return value


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be non-empty text")
    return value


def _safe_code(value: Any, field: str) -> str:
    text = _required_text(value, field)
    if not labeler.command_labeler.SAFE_CODE.fullmatch(text):
        raise ValueError(f"{field} is not a short snake_case code")
    return text


def _index_list(value: Any, field: str, event_count: int) -> list[int]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array")
    if any(isinstance(item, bool) or not isinstance(item, int) for item in value):
        raise ValueError(f"{field} contains a non-integer index")
    if value != sorted(set(value)):
        raise ValueError(f"{field} must be sorted and unique")
    if any(item < 0 or item >= event_count for item in value):
        raise ValueError(f"{field} contains an out-of-range index")
    return value


def _event_digest(row: dict[str, Any]) -> str:
    payload = row.get("payload")
    if not isinstance(payload, dict) or payload.get("direction") != "tool_call":
        raise ValueError("labeling input contains a non-tool-call payload")
    tool_name = payload.get("tool_name")
    arguments = payload.get("args")
    if not isinstance(tool_name, str) or not tool_name or not isinstance(arguments, dict):
        raise ValueError("labeling input contains an invalid tool call")
    return labeler.sha256_text(labeler.canonical_json({"tool_name": tool_name, "arguments": arguments}))


def _trim_embedded(value: str) -> str:
    return value.rstrip(".,;:!?)]}")


def _stable_path(value: str) -> bool:
    return (
        len(value) >= 6
        and value not in {"/", "./", "../"}
        and not value.startswith("//")
        and any(char.isalnum() for char in value)
    )


def _stable_resource(value: str) -> bool:
    return (
        8 <= len(value) <= 2048
        and not any(char.isspace() for char in value)
        and bool(_STABLE_TOKEN.fullmatch(value))
        and any(char.isdigit() for char in value)
        and any(char in "_./:=+@%-" for char in value)
    )


def _stable_secret(value: str) -> bool:
    return (
        16 <= len(value) <= 4096
        and not any(char.isspace() for char in value)
        and bool(_STABLE_TOKEN.fullmatch(value))
        and any(char.isalpha() for char in value)
        and any(char.isdigit() for char in value)
    )


def _extract_string_identities(value: str, key: str) -> set[tuple[str, str]]:
    identities: set[tuple[str, str]] = set()
    for pattern, kind in (
        (_URL, "url"),
        (_ARN, "resource_id"),
        (_AZURE_RESOURCE, "resource_id"),
        (_GCP_RESOURCE, "resource_id"),
        (_UNIX_PATH, "path"),
        (_WINDOWS_PATH, "path"),
        (_ARTIFACT_NAME, "artifact"),
    ):
        for match in pattern.finditer(value):
            candidate = _trim_embedded(match.group(0))
            if kind != "path" or _stable_path(candidate):
                identities.add((kind, candidate))

    stripped = value.strip().strip("\"'")
    normalized_key = key.lower().replace("-", "_")
    if _PATH_KEY.search(normalized_key) and _stable_path(stripped) and ("/" in stripped or "\\" in stripped):
        identities.add(("path", stripped))
    if (
        _DATABASE_KEY.search(normalized_key)
        and len(stripped) >= 6
        and _STABLE_TOKEN.fullmatch(stripped)
        and any(char.isdigit() or char in "_./:=-" for char in stripped)
    ):
        identities.add(("database", stripped))
    if _RESOURCE_KEY.search(normalized_key) and _stable_resource(stripped):
        identities.add(("resource_id", stripped))
    if _ARTIFACT_KEY.search(normalized_key) and len(stripped) >= 6 and _STABLE_TOKEN.fullmatch(stripped):
        if any(char in "._/:=-" for char in stripped):
            identities.add(("artifact", stripped))
    if _SECRET_KEY.search(normalized_key):
        secret_candidates = [stripped]
        if stripped.lower().startswith("bearer "):
            secret_candidates.append(stripped[7:].strip())
        for candidate in secret_candidates:
            if _stable_secret(candidate):
                identities.add(("secret_literal", candidate))
    return identities


def _extract_exact_identities(arguments: dict[str, Any]) -> set[tuple[str, str]]:
    """Extract conservative exact identities without trusting model-produced facts."""
    identities: set[tuple[str, str]] = set()

    def visit(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                if not isinstance(child_key, str):
                    raise ValueError("tool arguments contain a non-text object key")
                visit(child, child_key)
        elif isinstance(value, list):
            for child in value:
                visit(child, key)
        elif isinstance(value, str):
            identities.update(_extract_string_identities(value, key))
        elif value is not None and not isinstance(value, (bool, int, float)):
            raise ValueError("tool arguments contain a non-JSON scalar")

    visit(arguments)
    return identities


def _validate_prepare_manifest(manifest: dict[str, Any], labeling_input: Path) -> None:
    if set(manifest) != _PREPARE_KEYS:
        raise ValueError("prepare manifest has an unsupported schema")
    model_id = manifest.get("model_id")
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("workflow") != "bounded_trajectory_proof"
        or model_id not in labeler.SUPPORTED_MODEL_IDS
        or manifest.get("prompt_version") != labeler.PROMPT_VERSION_BY_MODEL[model_id]
    ):
        raise ValueError("prepare manifest has an unsupported workflow, model, or prompt")
    if manifest.get("source_sha256") != labeler.command_labeler.sha256_file(labeling_input):
        raise ValueError("prepare manifest source hash mismatch")
    if manifest.get("system_prompt_sha256") != labeler.sha256_text(labeler.SYSTEM_PROMPT):
        raise ValueError("prepare manifest system prompt hash mismatch")
    for field in (
        "trajectory_count",
        "event_count",
        "record_count",
        "max_completion_tokens",
    ):
        _required_int(manifest.get(field), f"prepare manifest {field}")
    for field in ("max_trajectory_events", "max_serialized_chars"):
        _required_int(manifest.get(field), f"prepare manifest {field}", positive=True)
    if manifest.get("one_trajectory_per_record") is not True:
        raise ValueError("prepare manifest does not bind one trajectory per record")
    if manifest.get("temperature") != 0 or manifest.get("top_p") != 0.1:
        raise ValueError("prepare manifest sampling parameters changed")
    if manifest.get("reasoning_effort") != "low":
        raise ValueError("prepare manifest reasoning effort changed")
    if not isinstance(manifest.get("skipped"), list) or not isinstance(manifest.get("token_usage_estimate"), dict):
        raise ValueError("prepare manifest aggregate fields are invalid")
    for field in ("requests_sha256", "index_sha256", "trajectory_set_sha256"):
        _required_text(manifest.get(field), f"prepare manifest {field}")
    _required_text(manifest.get("split"), "prepare manifest split")


def _bind_corpus_and_input(
    corpus_rows: list[dict[str, Any]], input_rows: list[dict[str, Any]]
) -> tuple[list[scorer.Trajectory], dict[str, dict[str, Any]]]:
    trajectories, _ = scorer.build_trajectories(corpus_rows)
    corpus_actions: dict[str, dict[str, Any]] = {}
    corpus_actions_by_trajectory: dict[str, set[str]] = defaultdict(set)
    for row in corpus_rows:
        if row["surface"] != "action":
            continue
        case_id = _required_text(row.get("id"), "corpus case identity")
        corpus_actions[case_id] = row
        corpus_actions_by_trajectory[row["strata"]["trajectory_id"]].add(case_id)

    input_by_id: dict[str, dict[str, Any]] = {}
    input_by_trajectory: dict[str, set[str]] = defaultdict(set)
    for row in input_rows:
        if row.get("surface") != "action":
            raise ValueError("labeling input must contain action cases only")
        case_id = _required_text(row.get("id"), "labeling input case identity")
        if case_id in input_by_id:
            raise ValueError("labeling input contains a duplicate case identity")
        corpus_row = corpus_actions.get(case_id)
        if corpus_row is None or scorer.canonical_json(row) != scorer.canonical_json(corpus_row):
            raise ValueError("labeling input does not exactly match the complete corpus")
        trajectory_id = labeler.trajectory_identity(row)
        input_by_id[case_id] = row
        input_by_trajectory[trajectory_id].add(case_id)
    for trajectory_id, case_ids in input_by_trajectory.items():
        if case_ids != corpus_actions_by_trajectory[trajectory_id]:
            raise ValueError("labeling input contains a partial corpus trajectory")
    return trajectories, input_by_id


def _bind_index(
    index_object: dict[str, Any],
    prepare: dict[str, Any],
    input_rows: list[dict[str, Any]],
    input_by_id: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    if set(index_object) != {"schema_version", "records"} or index_object.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("labeler index has an unsupported schema")
    records = index_object.get("records")
    if not isinstance(records, dict):
        raise ValueError("labeler index records must be an object")
    expected_ids = [f"trajectory-{number:08d}" for number in range(1, len(records) + 1)]
    if list(records) != expected_ids:
        raise ValueError("labeler index record identities are not canonical and contiguous")

    grouped, skipped, split = labeler.group_trajectories(
        input_rows,
        max_trajectory_events=prepare["max_trajectory_events"],
        max_serialized_chars=prepare["max_serialized_chars"],
    )
    if split != prepare["split"] or skipped != prepare["skipped"]:
        raise ValueError("prepare manifest split or skipped trajectories mismatch")
    selected = grouped[: len(records)]
    if len(selected) != len(records):
        raise ValueError("labeler index has more records than eligible trajectories")

    record_to_trajectory: dict[str, str] = {}
    for record_id, expected_trajectory in zip(expected_ids, selected, strict=True):
        raw = records[record_id]
        if not isinstance(raw, dict) or set(raw) != {
            "trajectory_sha256",
            "input_sha256",
            "split",
            "event_count",
            "events",
        }:
            raise ValueError("labeler index record has an unsupported schema")
        if raw.get("trajectory_sha256") != expected_trajectory["trajectory_sha256"]:
            raise ValueError("labeler index trajectory hash mismatch")
        if raw.get("input_sha256") != labeler.sha256_text(
            labeler.canonical_json(expected_trajectory["request_events"])
        ):
            raise ValueError("labeler index trajectory input hash mismatch")
        if raw.get("split") != split or raw.get("event_count") != len(expected_trajectory["events"]):
            raise ValueError("labeler index split or event count mismatch")
        raw_events = raw.get("events")
        if not isinstance(raw_events, list) or len(raw_events) != len(expected_trajectory["events"]):
            raise ValueError("labeler index events are incomplete")
        trajectory_ids: set[str] = set()
        for event_index, (event_meta, expected_event) in enumerate(
            zip(raw_events, expected_trajectory["events"], strict=True)
        ):
            if not isinstance(event_meta, dict) or set(event_meta) != {
                "id",
                "event_index",
                "sequence_index",
                "call_index",
                "input_sha256",
            }:
                raise ValueError("labeler index event has an unsupported schema")
            case_id = event_meta.get("id")
            row = input_by_id.get(case_id)
            if row is None or case_id != expected_event["id"]:
                raise ValueError("labeler index references an unknown or misordered case")
            if (
                event_meta.get("event_index") != event_index
                or event_meta.get("sequence_index") != expected_event["sequence_index"]
                or event_meta.get("call_index") != expected_event["call_index"]
                or event_meta.get("input_sha256") != _event_digest(row)
            ):
                raise ValueError("labeler index event identity, order, or hash mismatch")
            trajectory_ids.add(labeler.trajectory_identity(row))
        if len(trajectory_ids) != 1:
            raise ValueError("labeler index record mixes trajectory identities")
        record_to_trajectory[record_id] = next(iter(trajectory_ids))

    if prepare["trajectory_count"] != len(records) or prepare["record_count"] != len(records):
        raise ValueError("prepare manifest trajectory or record count mismatch")
    if prepare["event_count"] != sum(item["event_count"] for item in records.values()):
        raise ValueError("prepare manifest event count mismatch")
    selected_hashes = [records[record_id]["trajectory_sha256"] for record_id in expected_ids]
    if prepare["trajectory_set_sha256"] != labeler.sha256_text(labeler.canonical_json(selected_hashes)):
        raise ValueError("prepare manifest trajectory set hash mismatch")
    return records, record_to_trajectory


def _validate_proof(
    proof: Any,
    *,
    terminal_event: int,
    event_count: int,
    event_arguments: dict[int, dict[str, Any]],
) -> tuple[str, str, bool]:
    if not isinstance(proof, dict) or set(proof) != _PROOF_KEYS:
        raise ValueError("completed proof has an unsupported schema")
    proof_id = _safe_code(proof.get("proof_id"), "proof identity")
    proof_type = proof.get("proof_type")
    if proof_type not in labeler.PROOF_IDENTITY:
        raise ValueError("completed proof has an unsupported proof class")
    continuity = proof.get("identity_continuity")
    if continuity not in labeler.PROOF_IDENTITY[proof_type]:
        raise ValueError("completed proof identity continuity is invalid")
    _safe_code(proof.get("identity_ref"), "proof identity reference")
    event_indexes = _index_list(proof.get("event_indexes"), "proof event indexes", event_count)
    predecessors = _index_list(proof.get("predecessor_indexes"), "proof predecessors", event_count)
    if proof.get("terminal_event_index") != terminal_event or terminal_event not in event_indexes:
        raise ValueError("completed proof terminal identity mismatch")
    if predecessors != [index for index in event_indexes if index != terminal_event]:
        raise ValueError("completed proof predecessors do not exactly reference prior proof events")
    if any(index >= terminal_event for index in predecessors):
        raise ValueError("completed proof predecessor is not earlier than its terminal event")
    if proof_type in labeler.CHAIN_PROOF_TYPES and not predecessors:
        raise ValueError("completed chain proof has no predecessor")
    if proof_type == "atomic_literal_malicious_action" and (
        event_indexes != [terminal_event] or predecessors or continuity != "literal_atomic"
    ):
        raise ValueError("completed atomic proof is not literal and self-contained")
    if proof_type == "atomic_literal_malicious_action":
        # An offline model may propose an atomic candidate, but its assertion is
        # not itself a deterministic proof. Atomic candidates must be confirmed
        # by a separate literal/rule verifier before they can become benchmark
        # ground truth. Until that verifier is bound here, fail closed.
        lineage_proved = False
    else:
        allowed_kinds = _CONTINUITY_KINDS[continuity]
        identities_by_event = [
            {identity for identity in _extract_exact_identities(event_arguments[index]) if identity[0] in allowed_kinds}
            for index in event_indexes
        ]
        lineage_proved = bool(identities_by_event) and bool(set.intersection(*identities_by_event))
    _safe_code(proof.get("reason_code"), "proof reason code")
    return proof_id, proof_type, lineage_proved


def _validate_event_label(row: dict[str, Any], event_count: int) -> None:
    event = row.get("label")
    if not isinstance(event, dict) or set(event) != _EVENT_LABEL_KEYS:
        raise ValueError("collected event label has an unsupported schema")
    event_index = _required_int(event.get("event_index"), "event index")
    if event_index >= event_count:
        raise ValueError("collected event index is out of range")
    verdict = event.get("verdict")
    disposition = event.get("disposition")
    confidence = event.get("confidence")
    if (
        verdict not in labeler.VERDICTS
        or disposition not in labeler.DISPOSITIONS
        or confidence not in labeler.CONFIDENCES
    ):
        raise ValueError("collected event label contains an invalid enum")
    if (verdict == "deterministic_malicious") != (disposition == "block"):
        raise ValueError("collected block and deterministic verdict disagree")
    if verdict == "contextual_or_dual_use" and disposition != "detect_only":
        raise ValueError("collected contextual event is not detect-only")
    if verdict in {"benign", "invalid"} and disposition != "allow":
        raise ValueError("collected benign or invalid event is not allowed")
    facts = event.get("facts")
    if not isinstance(facts, dict) or set(facts) != _FACT_KEYS:
        raise ValueError("collected ActionFacts have an unsupported schema")
    enum_fields = {
        "operation": labeler.OPERATIONS,
        "resource": labeler.RESOURCES,
        "scope": labeler.SCOPES,
        "sensitivity": labeler.SENSITIVITIES,
        "destination_trust": labeler.DESTINATION_TRUST,
        "control_flow": labeler.CONTROL_FLOW,
        "result": labeler.RESULTS,
    }
    if any(facts.get(field) not in allowed for field, allowed in enum_fields.items()):
        raise ValueError("collected ActionFacts contain an invalid enum")
    refs = facts.get("identity_refs")
    if not isinstance(refs, list) or refs != sorted(set(refs)):
        raise ValueError("collected ActionFact identity references are not sorted and unique")
    for ref in refs:
        _safe_code(ref, "ActionFact identity reference")
    proof_ids = event.get("completed_proof_ids")
    if not isinstance(proof_ids, list) or proof_ids != sorted(set(proof_ids)):
        raise ValueError("collected completed proof identities are not sorted and unique")
    for proof_id in proof_ids:
        _safe_code(proof_id, "completed proof identity")
    predecessors = _index_list(event.get("predecessor_indexes"), "event predecessors", event_count)
    if any(index >= event_index for index in predecessors):
        raise ValueError("event predecessor is not earlier than the event")
    _safe_code(event.get("reason_code"), "event reason code")
    completed = event.get("completed_proofs")
    if not isinstance(completed, list):
        raise ValueError("collected completed proofs must be an array")
    if (verdict == "deterministic_malicious") != bool(completed):
        raise ValueError("deterministic verdict and completed proof presence disagree")


def _bind_collected_labels(
    rows: list[dict[str, Any]],
    manifest: dict[str, Any],
    prepare: dict[str, Any],
    records: dict[str, dict[str, Any]],
    labels_path: Path,
) -> tuple[dict[str, dict[int, dict[str, Any]]], int]:
    if set(manifest) != _COLLECT_KEYS:
        raise ValueError("collected-label manifest has an unsupported schema")
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("workflow") != "bounded_trajectory_proof"
        or manifest.get("model_id") != prepare["model_id"]
        or manifest.get("prompt_version") != prepare["prompt_version"]
        or manifest.get("requests_sha256") != prepare["requests_sha256"]
        or manifest.get("index_sha256") != prepare["index_sha256"]
    ):
        raise ValueError("collected-label manifest does not match the prepare manifest")
    if manifest.get("labels_sha256") != labeler.command_labeler.sha256_file(labels_path):
        raise ValueError("collected-label manifest labels hash mismatch")
    if manifest.get("label_count") != len(rows):
        raise ValueError("collected-label manifest label count mismatch")
    _required_text(manifest.get("job_arn"), "collected-label job identity")
    token_usage = manifest.get("token_usage")
    if not isinstance(token_usage, dict) or set(token_usage) != {"input_tokens", "output_tokens"}:
        raise ValueError("collected-label token usage has an unsupported schema")
    for field in token_usage:
        _required_int(token_usage[field], f"collected-label {field}")

    by_record: dict[str, dict[int, dict[str, Any]]] = defaultdict(dict)
    seen_case_ids: set[str] = set()
    review_required = 0
    for row in rows:
        if set(row) != _COLLECTED_LABEL_KEYS or row.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("collected label has an unsupported schema")
        record_id = row.get("trajectory_record_id")
        record = records.get(record_id)
        if record is None:
            raise ValueError("collected label references an unknown trajectory record")
        event_index = row.get("label", {}).get("event_index") if isinstance(row.get("label"), dict) else None
        if isinstance(event_index, bool) or not isinstance(event_index, int):
            raise ValueError("collected label has no integer event index")
        if event_index in by_record[record_id]:
            raise ValueError("collected label repeats a trajectory event")
        if event_index < 0 or event_index >= len(record["events"]):
            raise ValueError("collected label event index is out of range")
        expected = record["events"][event_index]
        case_id = row.get("id")
        if case_id in seen_case_ids or case_id != expected["id"]:
            raise ValueError("collected label case identity is duplicate or mismatched")
        seen_case_ids.add(case_id)
        if (
            row.get("prompt_version") != prepare["prompt_version"]
            or row.get("model_id") != prepare["model_id"]
            or row.get("input_sha256") != expected["input_sha256"]
            or row.get("trajectory_input_sha256") != record["input_sha256"]
            or row.get("sequence_index") != expected["sequence_index"]
            or row.get("call_index") != expected["call_index"]
        ):
            raise ValueError("collected label hash, model, trajectory, or order identity mismatch")
        _validate_event_label(row, record["event_count"])
        expected_review = row["label"]["confidence"] == "low" or row["label"]["verdict"] == "invalid"
        if row.get("review_required") is not expected_review:
            raise ValueError("collected label review flag mismatch")
        review_required += int(expected_review)
        by_record[record_id][event_index] = row
    if manifest.get("review_required_count") != review_required:
        raise ValueError("collected-label manifest review count mismatch")

    errors = manifest.get("errors")
    if not isinstance(errors, list):
        raise ValueError("collected-label errors must be an array")
    error_records: set[str] = set()
    for error in errors:
        if not isinstance(error, dict) or set(error) != {"record_id", "reason", "retryable"}:
            raise ValueError("collected-label error has an unsupported schema")
        record_id = error.get("record_id")
        if record_id not in records or record_id in error_records or error.get("retryable") is not True:
            raise ValueError("collected-label error identity or retryability is invalid")
        if error.get("reason") not in {
            "bedrock_record_error",
            "invalid_model_output",
            "missing_result_record",
        }:
            raise ValueError("collected-label error reason is unsupported")
        error_records.add(record_id)
    complete_records = {
        record_id
        for record_id, events in by_record.items()
        if set(events) == set(range(records[record_id]["event_count"]))
    }
    partial_records = set(by_record) - complete_records
    if partial_records:
        raise ValueError("collected labels contain a partial trajectory record")
    if complete_records & error_records or set(records) - complete_records != error_records:
        raise ValueError("collected-label errors do not exactly account for unlabeled records")
    return by_record, review_required


def _validated_proofs(
    events: dict[int, dict[str, Any]],
    event_count: int,
    event_arguments: dict[int, dict[str, Any]],
) -> tuple[list[str], list[str]]:
    classes: list[str] = []
    rejected_classes: list[str] = []
    seen_proof_ids: set[str] = set()
    for event_index in range(event_count):
        row = events[event_index]
        event = row["label"]
        proof_ids = event["completed_proof_ids"]
        completed = event["completed_proofs"]
        if [proof.get("proof_id") for proof in completed] != proof_ids:
            raise ValueError("completed proof objects do not exactly match their event references")
        expected_predecessors: set[int] = set()
        for proof in completed:
            proof_id, proof_type, lineage_proved = _validate_proof(
                proof,
                terminal_event=event_index,
                event_count=event_count,
                event_arguments=event_arguments,
            )
            if proof_id in seen_proof_ids:
                raise ValueError("completed proof identity is repeated in a trajectory")
            seen_proof_ids.add(proof_id)
            expected_predecessors.update(proof["predecessor_indexes"])
            if lineage_proved:
                classes.append(proof_type)
            else:
                rejected_classes.append(proof_type)
        if event["predecessor_indexes"] != sorted(expected_predecessors):
            raise ValueError("event predecessors do not exactly match its completed proofs")
        qualifies = (
            event["verdict"] == "deterministic_malicious" and event["disposition"] == "block" and bool(completed)
        )
        if qualifies != bool(completed):
            raise ValueError("completed proof does not terminate in a deterministic block")
    return classes, rejected_classes


def finalize(args: argparse.Namespace) -> dict[str, Any]:
    corpus_rows = _load_jsonl(args.corpus)
    input_rows = _load_jsonl(args.labeling_input)
    collected_rows = _load_jsonl(args.labels, allow_empty=True)
    prepare = _load_object(args.prepare_manifest)
    index_object = _load_object(args.index)
    collected_manifest = _load_object(args.labels_manifest)

    _validate_prepare_manifest(prepare, args.labeling_input)
    if prepare["index_sha256"] != labeler.command_labeler.sha256_file(args.index):
        raise ValueError("prepare manifest index hash mismatch")
    trajectories, input_by_id = _bind_corpus_and_input(corpus_rows, input_rows)
    records, record_to_trajectory = _bind_index(index_object, prepare, input_rows, input_by_id)
    by_record, _ = _bind_collected_labels(
        collected_rows,
        collected_manifest,
        prepare,
        records,
        args.labels,
    )

    proof_classes_by_trajectory: dict[str, list[str]] = defaultdict(list)
    rejected_proof_classes: Counter[str] = Counter()
    for record_id, events in by_record.items():
        event_arguments = {
            event["event_index"]: input_by_id[event["id"]]["payload"]["args"] for event in records[record_id]["events"]
        }
        validated, rejected = _validated_proofs(
            events,
            records[record_id]["event_count"],
            event_arguments,
        )
        proof_classes_by_trajectory[record_to_trajectory[record_id]].extend(validated)
        rejected_proof_classes.update(rejected)

    labels: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    label_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    proof_class_counts: Counter[str] = Counter()
    labeled_trajectories = {record_to_trajectory[record_id] for record_id in by_record}
    for trajectory in trajectories:
        classes = sorted(proof_classes_by_trajectory.get(trajectory.trajectory_id, []))
        proof_class_counts.update(classes)
        source_counts[trajectory.source_truth] += 1
        if trajectory.source_truth == "benign":
            final_truth = "benign"
            if classes:
                conflicts.append(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "kind": CONFLICT_KIND,
                        "trajectory_id": trajectory.trajectory_id,
                        "trajectory_identity_sha256": trajectory.identity_sha256,
                        "source_truth": "benign",
                        "proposed_truth": "malicious",
                        "proof_classes": sorted(set(classes)),
                    }
                )
        else:
            final_truth = "malicious" if classes else "unknown"
        label_counts[final_truth] += 1
        labels.append(
            {
                "schema_version": SCHEMA_VERSION,
                "trajectory_id": trajectory.trajectory_id,
                "trajectory_identity_sha256": trajectory.identity_sha256,
                "source_truth": final_truth,
            }
        )

    output_manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": scorer.PROOF_KIND,
        "corpus_sha256": scorer.sha256_file(args.corpus),
        "trajectory_identity_set_sha256": scorer.trajectory_identity_set_sha256(trajectories),
        "labels_sha256": "",
        "trajectory_count": len(trajectories),
        "label_count": len(labels),
    }
    summary = {
        "schema_version": SCHEMA_VERSION,
        "kind": SUMMARY_KIND,
        "trajectory_count": len(trajectories),
        "labeled_trajectory_count": len(labeled_trajectories),
        "unlabeled_trajectory_count": len(trajectories) - len(labeled_trajectories),
        "label_counts": {key: label_counts.get(key, 0) for key in ("benign", "malicious", "unknown")},
        "source_truth_counts": {
            key: source_counts.get(key, 0) for key in ("benign", "malicious", "sensitive", "unknown")
        },
        "conflict_count": len(conflicts),
        "abstention_count": label_counts.get("unknown", 0),
        "validated_proof_count": sum(proof_class_counts.values()),
        "proof_class_counts": {key: proof_class_counts.get(key, 0) for key in sorted(labeler.PROOF_IDENTITY)},
        "lineage_rejected_proof_count": sum(rejected_proof_classes.values()),
        "lineage_rejected_proof_class_counts": {
            key: rejected_proof_classes.get(key, 0) for key in sorted(labeler.PROOF_IDENTITY)
        },
    }

    labels_data = b"".join(scorer.canonical_json(row) for row in labels)
    output_manifest["labels_sha256"] = scorer.sha256_bytes(labels_data)
    conflicts_data = b"".join(scorer.canonical_json(row) for row in conflicts)
    manifest_path = args.output.with_suffix(".manifest.json")
    summary_path = args.summary or args.output.with_suffix(".summary.json")
    conflicts_path = args.conflicts or args.output.with_suffix(".conflicts.jsonl")
    _atomic_write(args.output, labels_data)
    _atomic_write(manifest_path, scorer.canonical_json(output_manifest))
    _atomic_write(summary_path, scorer.canonical_json(summary))
    _atomic_write(conflicts_path, conflicts_data)
    return summary


def _atomic_write(path: Path, data: bytes) -> None:
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


def main() -> int:
    summary = finalize(parse_args())
    print(
        json.dumps(
            {
                "trajectory_count": summary["trajectory_count"],
                "conflict_count": summary["conflict_count"],
                "abstention_count": summary["abstention_count"],
                "validated_proof_count": summary["validated_proof_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
