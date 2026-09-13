#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize the pinned DTap trajectory release into bounded DefenseClaw cases.

The source judge is used only as candidate trajectory truth: a successful
trajectory label does not prove that every tool call in that trajectory was
malicious.  This normalizer therefore emits only English tasks with a real,
non-empty tool argument object and a matching, non-empty tool-result row that
is not explicitly an error.  Agent prose, prompts, evaluator prose, judge
text, and result text are not action evidence.

Tool results are paired by tool name and FIFO call order.  This preserves
parallel-call identity without treating an adjacent unrelated row as the
result.  Event order and identity are retained within bounded chunks; no
cross-trajectory or semantic chain inference is performed, and no authority
is inferred from a trajectory label.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import warnings
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
DATASET_ID = "AI-Secure/DTap-Bench-Agent-Trajectories"
SOURCE_URL = f"https://huggingface.co/datasets/{DATASET_ID}"
LICENSE = "Apache-2.0"
PINNED_REVISION = "836caf2fdd78b888ddd14fb62dc038e932e17898"
NON_ENGLISH_SCRIPT = re.compile(
    "[\u0370-\u052f\u0590-\u08ff\u0900-\u109f\u1780-\u18af\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]"
)
MAX_EVENTS = 64
MALICIOUS_EXCLUSION_REASON = (
    "The source attack_success judge proves the complete trajectory, not this emitted chunk; "
    "the DTap adapter has no independent exact proof verifier, so the chunk is excluded from "
    "scored deterministic truth pending proof."
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--revision", default=PINNED_REVISION)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _parse_literal_or_json(value: str) -> Any:
    text = value.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                return ast.literal_eval(text)
        except (SyntaxError, ValueError):
            return None


def _result_objects(state: Any) -> list[dict[str, Any]]:
    """Extract bounded, structured result envelopes without executing source text."""

    pending: deque[Any] = deque([state])
    objects: list[dict[str, Any]] = []
    seen = 0
    while pending and seen < 32:
        value = pending.popleft()
        seen += 1
        if isinstance(value, str):
            parsed = _parse_literal_or_json(value)
            if parsed is not None and parsed != value:
                pending.append(parsed)
            continue
        if isinstance(value, dict):
            objects.append(value)
            for key in ("text", "result", "data", "response", "output"):
                nested = value.get(key)
                if isinstance(nested, (dict, list, str)):
                    pending.append(nested)
        elif isinstance(value, list):
            pending.extend(value[:32])
    return objects


def result_outcome(row: dict[str, Any] | None) -> str:
    """Classify a matched result as succeeded, failed, or unknown."""

    if not row or row.get("role") != "tool" or "state" not in row:
        return "unknown"
    objects = _result_objects(row.get("state"))
    failure = False
    success = False
    failure_statuses = {"error", "failed", "failure", "exception"}
    for result in objects:
        if result.get("success") is False:
            failure = True
        if isinstance(result.get("return_code"), int) and result["return_code"] != 0:
            failure = True
        if isinstance(result.get("status"), str) and result["status"].lower() in failure_statuses:
            failure = True
        if result.get("error") not in (None, "", [], {}):
            failure = True
        if result.get("success") is True or result.get("return_code") == 0:
            success = True
    if failure:
        return "failed"
    if success:
        return "succeeded"
    return "unknown"


def _real_arguments(arguments: Any) -> bool:
    if not isinstance(arguments, dict) or not arguments:
        return False
    for value in arguments.values():
        if value is None or value == "" or value == [] or value == {}:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return True
    return False


def _has_result_evidence(state: Any) -> bool:
    if state is None or state == {} or state == []:
        return False
    if isinstance(state, str) and not state.strip():
        return False
    if isinstance(state, str) and re.match(r"^(?:error|exception|failed)\b", state.strip(), re.IGNORECASE):
        return False
    return True


def normalized_events(trace: dict[str, Any]) -> list[dict[str, Any]]:
    trajectory = trace.get("trajectory")
    if not isinstance(trajectory, list):
        return []
    pending: defaultdict[str, deque[dict[str, Any]]] = defaultdict(deque)
    events: list[dict[str, Any]] = []
    call_ordinal = 0
    for index, row in enumerate(trajectory):
        if not isinstance(row, dict):
            continue
        if row.get("role") == "agent":
            metadata = row.get("metadata")
            if not isinstance(metadata, dict):
                continue
            tool_name = metadata.get("tool_name")
            arguments = metadata.get("tool_params")
            if not isinstance(tool_name, str) or not tool_name.strip() or not _real_arguments(arguments):
                continue
            pending[tool_name].append(
                {
                    "_index": index,
                    "_ordinal": call_ordinal,
                    "args": arguments,
                    "dialect": "none",
                    "tool_name": tool_name,
                }
            )
            call_ordinal += 1
            continue
        if row.get("role") != "tool":
            continue
        metadata = row.get("metadata")
        tool_name = metadata.get("tool_name") if isinstance(metadata, dict) else None
        if not isinstance(tool_name, str) or not tool_name.strip() or not pending[tool_name]:
            continue
        event = pending[tool_name].popleft()
        state = row.get("state")
        if not _has_result_evidence(state):
            continue
        outcome = result_outcome(row)
        if outcome == "failed":
            continue
        event["outcome"] = outcome
        events.append(event)
    events.sort(key=lambda event: event["_index"])
    for event in events:
        event["offset_seconds"] = event["_ordinal"]
        event.pop("_index", None)
    return events


def path_class(path: Path) -> str | None:
    if "benign" in path.parts:
        return "benign"
    if "malicious" in path.parts:
        return "malicious"
    return None


def split_for(group: str) -> str:
    bucket = int.from_bytes(hashlib.sha256(group.encode("utf-8")).digest()[:2], "big") % 100
    if bucket < 70:
        return "development"
    if bucket < 85:
        return "validation"
    return "test"


def bounded_payloads(events: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    with_ordinals = []
    for ordinal, event in enumerate(events):
        copied = dict(event)
        copied.setdefault("_ordinal", ordinal)
        with_ordinals.append(copied)
    return bounded_payloads_from_source(with_ordinals, len(with_ordinals))


def bounded_payloads_from_source(
    events: list[dict[str, Any]], source_event_count: int
) -> list[tuple[str, dict[str, Any]]]:
    """Chunk by source call windows while emitting only evidenced events."""

    projected: list[tuple[str, dict[str, Any]]] = []
    if source_event_count <= 0:
        return projected
    by_ordinal = {event["_ordinal"]: event for event in events}
    for start in range(0, source_event_count, MAX_EVENTS):
        source_chunk = [
            by_ordinal[ordinal]
            for ordinal in range(start, min(start + MAX_EVENTS, source_event_count))
            if ordinal in by_ordinal
        ]
        if not source_chunk:
            continue
        chunk = [{key: value for key, value in event.items() if not key.startswith("_")} for event in source_chunk]
        if len(chunk) == 1:
            event = chunk[0]
            projected.append(
                (
                    "action",
                    {
                        "args": event["args"],
                        "dialect": event["dialect"],
                        "direction": "tool_call",
                        "tool_name": event["tool_name"],
                    },
                )
            )
        else:
            projected.append(("stateful", {"events": chunk}))
    return projected


def real_call_count(trace: dict[str, Any]) -> int:
    trajectory = trace.get("trajectory")
    if not isinstance(trajectory, list):
        return 0
    count = 0
    for row in trajectory:
        if not isinstance(row, dict) or row.get("role") != "agent":
            continue
        metadata = row.get("metadata")
        if not isinstance(metadata, dict):
            continue
        if isinstance(metadata.get("tool_name"), str) and metadata["tool_name"].strip() and _real_arguments(
            metadata.get("tool_params")
        ):
            count += 1
    return count


def truth_contract(source_truth: str, domain: str) -> dict[str, Any]:
    common = {
        "label_confidence": "high",
        "label_source": "source:deterministic_environment_judge",
        "source_truth": source_truth,
    }
    if source_truth == "malicious":
        return {
            **common,
            "applicability": "out_of_scope",
            "categories": [
                "execution_grounded",
                "source_trajectory_success",
                "trajectory_success_candidate",
                "proof_pending",
                domain,
                source_truth,
            ],
            "deterministic_truth": "contextual_or_dual_use",
            "exclusion_reason": MALICIOUS_EXCLUSION_REASON,
            "expected_disposition": "detect_only",
        }
    return {
        **common,
        "applicability": "in_scope",
        "categories": ["execution_grounded", "judge_confirmed", domain, source_truth],
        "deterministic_truth": "benign",
        "expected_disposition": "allow",
    }


def normalize(root: Path, revision: str) -> tuple[list[dict[str, Any]], Counter[str]]:
    if revision != PINNED_REVISION:
        raise ValueError(f"unsupported DTap revision {revision!r}; expected {PINNED_REVISION}")
    rows: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for trace_path in sorted(root.rglob("*.json")):
        if trace_path.name == "judge_result.json":
            continue
        truth = path_class(trace_path.relative_to(root))
        if truth is None:
            counts["unclassified_path"] += 1
            continue
        judge_path = trace_path.with_name("judge_result.json")
        if not judge_path.is_file():
            counts["missing_judge"] += 1
            continue
        try:
            trace = load_object(trace_path)
            judge = load_object(judge_path)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            counts["unreadable_or_invalid_source"] += 1
            continue
        proved = judge.get("task_success") is True if truth == "benign" else judge.get("attack_success") is True
        if not proved:
            counts[f"unproved_{truth}"] += 1
            continue
        events = normalized_events(trace)
        if not events:
            counts["no_tool_events"] += 1
            continue
        task = trace.get("task_info")
        if not isinstance(task, dict):
            counts["invalid_task_info"] += 1
            continue
        domain = task.get("domain")
        task_id = task.get("task_id")
        if not isinstance(domain, str) or not domain or not isinstance(task_id, str) or not task_id:
            counts["invalid_task_identity"] += 1
            continue
        instruction = task.get("original_instruction")
        if not isinstance(instruction, str) or not re.search(r"[A-Za-z]", instruction) or NON_ENGLISH_SCRIPT.search(instruction):
            counts["non_english"] += 1
            continue
        relative = trace_path.relative_to(root).as_posix()
        identity = hashlib.sha256(relative.encode("utf-8")).hexdigest()[:24]
        malicious = truth == "malicious"
        split_group = hashlib.sha256(f"{domain}:{task_id}".encode("utf-8")).hexdigest()[:24]
        projected = bounded_payloads_from_source(events, real_call_count(trace))
        for chunk_index, (surface, payload) in enumerate(projected):
            case_id = f"dtap-agent-trajectories/{identity}"
            if len(projected) > 1:
                case_id += f"/chunk-{chunk_index:03d}"
            rows.append(
                {
                    "id": case_id,
                    "payload": payload,
                    "schema_version": SCHEMA_VERSION,
                    "source": {
                        "dataset": DATASET_ID,
                        "license": LICENSE,
                        "original_id": relative,
                        "redistribution": "download-only",
                        "revision": revision,
                    },
                    "split": split_for(split_group),
                    "strata": {
                        "campaign": str(task.get("risk_category") or "benign"),
                        "domain": domain,
                        "hard_negative": not malicious,
                        "split_group": split_group,
                    },
                    "surface": surface,
                    "truth": truth_contract(truth, domain),
                }
            )
            counts[surface] += 1
            counts["cases"] += 1
            counts[f"{truth}_cases"] += 1
            if malicious:
                counts["proof_pending_cases"] += 1
        counts[truth] += 1
        counts[split_for(split_group)] += 1
        counts["events"] += len(events)
    rows.sort(key=lambda row: row["id"])
    return rows, counts


def main() -> int:
    args = parse_args()
    rows, counts = normalize(args.root, args.revision)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "dataset": DATASET_ID,
        "license": LICENSE,
        "output_sha256": sha256_file(args.output),
        "revision": args.revision,
        "row_count": len(rows),
        "schema_version": SCHEMA_VERSION,
        "source_url": SOURCE_URL,
        "counts": dict(sorted(counts.items())),
        "label_limitation": (
            "Successful benign trajectories are in-scope benign FPR truth. Source attack_success labels prove only "
            "the complete malicious trajectory, not each emitted chunk; malicious chunks remain out-of-scope, "
            "detect-only, contextual trajectory-success candidates with proof pending because this adapter has no "
            "independent exact proof verifier. Only English trajectories with real tool arguments and matching "
            "non-error result evidence are projected; prompts, prose, evaluator/judge text, and result content are "
            "not authoritative action evidence."
        ),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"rows": len(rows), "counts": dict(sorted(counts.items()))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
