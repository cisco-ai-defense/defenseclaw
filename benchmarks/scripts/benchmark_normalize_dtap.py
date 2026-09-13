#!/usr/bin/env python3
"""Normalize judge-confirmed DTAP trajectories into DefenseClaw stateful cases."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import warnings
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
DATASET_ID = "AI-Secure/DTap-Bench-Agent-Trajectories"
SOURCE_URL = f"https://huggingface.co/datasets/{DATASET_ID}"
LICENSE = "Apache-2.0"
NON_ENGLISH_SCRIPT = re.compile(
    "[\u0370-\u052f\u0590-\u08ff\u0900-\u109f\u1780-\u18af\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]"
)
MAX_EVENTS = 64


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--revision", required=True)
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


def result_outcome(row: dict[str, Any] | None) -> str:
    if not row or row.get("role") != "tool":
        return "unknown"
    state = row.get("state")
    if not isinstance(state, str):
        return "unknown"
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            envelope = ast.literal_eval(state)
    except (SyntaxError, ValueError):
        return "unknown"
    if not isinstance(envelope, dict):
        return "unknown"
    text = envelope.get("text")
    if not isinstance(text, str):
        return "unknown"
    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        return "unknown"
    if not isinstance(result, dict):
        return "unknown"
    if result.get("success") is True or result.get("return_code") == 0:
        return "succeeded"
    if result.get("success") is False or isinstance(result.get("return_code"), int):
        return "failed"
    return "unknown"


def normalized_events(trace: dict[str, Any]) -> list[dict[str, Any]]:
    trajectory = trace.get("trajectory")
    if not isinstance(trajectory, list):
        return []
    events: list[dict[str, Any]] = []
    for index, row in enumerate(trajectory):
        if not isinstance(row, dict) or row.get("role") != "agent":
            continue
        metadata = row.get("metadata")
        if not isinstance(metadata, dict):
            continue
        tool_name = metadata.get("tool_name")
        arguments = metadata.get("tool_params")
        if not isinstance(tool_name, str) or not tool_name or not isinstance(arguments, dict):
            continue
        outcome_row = trajectory[index + 1] if index + 1 < len(trajectory) else None
        events.append(
            {
                "args": arguments,
                "dialect": "none",
                "offset_seconds": len(events),
                "outcome": result_outcome(outcome_row if isinstance(outcome_row, dict) else None),
                "tool_name": tool_name,
            }
        )
    return events


def path_class(path: Path) -> str | None:
    parts = path.parts
    if "benign" in parts:
        return "benign"
    if "malicious" in parts:
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
    projected: list[tuple[str, dict[str, Any]]] = []
    for start in range(0, len(events), MAX_EVENTS):
        chunk = events[start : start + MAX_EVENTS]
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


def normalize(root: Path, revision: str) -> tuple[list[dict[str, Any]], Counter[str]]:
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
        if (
            not isinstance(instruction, str)
            or not re.search(r"[A-Za-z]", instruction)
            or NON_ENGLISH_SCRIPT.search(instruction)
        ):
            counts["non_english"] += 1
            continue
        relative = trace_path.relative_to(root).as_posix()
        identity = hashlib.sha256(relative.encode("utf-8")).hexdigest()[:24]
        malicious = truth == "malicious"
        split_group = hashlib.sha256(f"{domain}:{task_id}".encode()).hexdigest()[:24]
        split = split_for(split_group)
        projected = bounded_payloads(events)
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
                    "split": split,
                    "strata": {
                        "campaign": str(task.get("risk_category") or "benign"),
                        "domain": domain,
                        "hard_negative": not malicious,
                        "split_group": split_group,
                    },
                    "surface": surface,
                    "truth": {
                        "applicability": "in_scope",
                        "categories": ["execution_grounded", "judge_confirmed", domain, truth],
                        "deterministic_truth": truth,
                        "expected_disposition": "block" if malicious else "allow",
                        "label_confidence": "high",
                        "label_source": "source:deterministic_environment_judge",
                        "source_truth": truth,
                    },
                }
            )
            counts[surface] += 1
            counts["cases"] += 1
        counts[truth] += 1
        counts[split] += 1
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
            "Only deterministic-judge-confirmed successful benign and malicious trajectories are retained; "
            "a trajectory label does not make every constituent tool call malicious."
        ),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"rows": len(rows), "counts": dict(sorted(counts.items()))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
