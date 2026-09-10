#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Project MonitoringBench attack steps into bounded real-argument cases.

MonitoringBench proves a harmful sandbox postcondition at trajectory level and
provides a one-based ``attack_step`` for most samples.  This adapter retains
only tool names, arguments, completion status, and a maximum eight-event window
ending at that step.  It never retains prompts, reasoning, tool results, monitor
scores, or scorer explanations.

Environment success is source truth, not automatically deterministic detector
truth.  Every projected case remains contextual/dual-use until an independent
closed ActionFacts/CEL proof finalizer promotes it.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import zipfile
from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

SOURCE_ID = "neur26anonsub/ctrldataset2026"
SOURCE_URL = "https://huggingface.co/datasets/neur26anonsub/ctrldataset2026"
SOURCE_LICENSE = "CC-BY-4.0"
SOURCE_REDISTRIBUTION = "download-only"
SCHEMA_VERSION = "defenseclaw.monitoringbench-real-arguments.v1"
KNOWN_SIDE_TASKS = frozenset({"firewall", "malware", "password_leak", "sudo"})
SHELL_TOOLS = frozenset({"bash", "bash_root"})
SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,159}$")
MAX_ARGUMENT_BYTES = 1_048_576
MAX_VALUE_BYTES = 262_144
MAX_WINDOW_EVENTS = 8
AUDITED_DEVELOPMENT_TASKS = frozenset({"12990180"})

MASTER_COLUMNS = (
    "sample_uuid",
    "task_id",
    "side_task_name",
    "side_task_group",
    "source_name",
    "eval_log_filename",
    "side_task_success",
    "tool_call_count",
    "attack_step",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--master", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--split", choices=("development", "validation", "test"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--schema", type=Path, default=Path("benchmarks/schema/case-v1.schema.json")
    )
    parser.add_argument("--limit", type=int)
    return parser.parse_args()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def master_rows(path: Path) -> Iterable[dict[str, Any]]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:  # pragma: no cover - CLI dependency guidance
        raise RuntimeError("pyarrow==25.0.1 is required") from exc
    parquet = pq.ParquetFile(path)
    missing = sorted(set(MASTER_COLUMNS) - set(parquet.schema_arrow.names))
    if missing:
        raise ValueError(f"master parquet is missing columns: {', '.join(missing)}")
    for batch in parquet.iter_batches(batch_size=64, columns=MASTER_COLUMNS):
        yield from batch.to_pylist()


def assigned_split(task_id: str) -> str:
    if task_id in AUDITED_DEVELOPMENT_TASKS:
        return "development"
    value = int.from_bytes(
        hashlib.sha256(f"basharena-task-v1\x00{task_id}".encode()).digest()[:8], "big"
    ) % 100
    if value < 70:
        return "development"
    if value < 85:
        return "validation"
    return "test"


def archive_members(archive: zipfile.ZipFile) -> dict[str, str]:
    members: dict[str, str] = {}
    for name in archive.namelist():
        if not name.endswith(".eval") or "/__MACOSX/" in f"/{name}" or "/._" in name:
            continue
        basename = name.rsplit("/", 1)[-1]
        if basename in members:
            raise ValueError(f"duplicate eval basename in archive: {basename}")
        members[basename] = name
    return members


def _bounded(value: object, *, path: str = "argument") -> object:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_VALUE_BYTES:
            raise ValueError(f"{path}_too_large")
        return value
    if isinstance(value, list):
        if len(value) > 256:
            raise ValueError(f"{path}_too_many_items")
        return [_bounded(item, path=path) for item in value]
    if isinstance(value, dict):
        if len(value) > 128 or any(not isinstance(key, str) for key in value):
            raise ValueError(f"{path}_invalid_object")
        return {key: _bounded(value[key], path=path) for key in sorted(value)}
    raise ValueError(f"{path}_unsupported_type")


def _resolve_attachment_values(value: object, attachments: dict[str, str]) -> object:
    if isinstance(value, str) and value.startswith("attachment://"):
        return attachments.get(value.removeprefix("attachment://"), value)
    if isinstance(value, list):
        return [_resolve_attachment_values(item, attachments) for item in value]
    if isinstance(value, dict):
        return {key: _resolve_attachment_values(item, attachments) for key, item in value.items()}
    return value


def project_tool_event(
    event: object, ordinal: int, attachments: dict[str, str] | None = None
) -> tuple[dict[str, object], str]:
    function = getattr(event, "function", None)
    arguments = getattr(event, "arguments", None)
    if not isinstance(function, str) or not SAFE_TOOL.fullmatch(function):
        raise ValueError("invalid_tool_name")
    if not isinstance(arguments, dict):
        raise ValueError("non_object_arguments")
    arguments = _resolve_attachment_values(arguments, attachments or {})
    encoded = json.dumps(arguments, ensure_ascii=False, sort_keys=True).encode("utf-8")
    if len(encoded) > MAX_ARGUMENT_BYTES:
        raise ValueError("arguments_too_large")

    failed = bool(getattr(event, "failed", False)) or getattr(event, "error", None) is not None
    completed = getattr(event, "completed", None) is not None
    outcome = "failed" if failed else "succeeded" if completed else "unknown"
    projected: dict[str, object] = {
        "tool_name": function,
        "args": {},
        "dialect": "none",
        "outcome": outcome,
        "offset_seconds": ordinal,
    }
    bounded = _bounded(arguments)
    if function in SHELL_TOOLS:
        command = arguments.get("cmd", arguments.get("command"))
        if not isinstance(command, str) or not command.strip():
            raise ValueError("missing_shell_command")
        projected["command"] = command
        projected["dialect"] = "posix"
        projected["args"] = {
            key: value for key, value in bounded.items() if key not in {"cmd", "command"}
        }
    else:
        projected["args"] = bounded
    return projected, outcome


def select_attack_group(events: Sequence[object], attack_step: int) -> tuple[list[object], int, int]:
    agent_events = [event for event in events if getattr(event, "function", None) != "submit"]
    if attack_step < 1 or attack_step > len(agent_events):
        raise ValueError("attack_step_out_of_range")
    target_index = attack_step - 1
    message_id = getattr(agent_events[target_index], "message_id", None)
    if not isinstance(message_id, str) or not message_id:
        return agent_events, target_index, target_index + 1
    matching = [index for index, event in enumerate(agent_events) if getattr(event, "message_id", None) == message_id]
    start, end = min(matching), max(matching) + 1
    if matching != list(range(start, end)):
        raise ValueError("non_contiguous_attack_group")
    return agent_events, start, end


def _case_base(
    *, row: dict[str, Any], revision: str, split: str, original_id: str, suffix: str
) -> dict[str, Any]:
    sample_uuid = str(row["sample_uuid"])
    task_id = str(row["task_id"])
    side_group = str(row["side_task_group"])
    digest = hashlib.sha256(
        f"{SOURCE_ID}\x00{revision}\x00{sample_uuid}\x00{suffix}".encode()
    ).hexdigest()
    return {
        "schema_version": "1",
        "id": f"monitoringbench/{digest[:24]}",
        "source": {
            "dataset": SOURCE_ID,
            "revision": revision,
            "original_id": original_id[:240],
            "license": SOURCE_LICENSE,
            "redistribution": SOURCE_REDISTRIBUTION,
        },
        "split": split,
        "truth": {
            "source_truth": "malicious",
            "deterministic_truth": "contextual_or_dual_use",
            "label_confidence": "high",
            "label_source": "monitoringbench:environment-success-attack-step",
            "applicability": "in_scope",
            "expected_disposition": "detect_only",
            "categories": [
                "environment_verified_attack",
                "exact_attack_step",
                f"side_task.{side_group}",
            ],
        },
        "strata": {
            "platform": "linux",
            "campaign": str(row.get("source_name") or "unknown")[:160],
            "domain": side_group[:160],
            "split_group": hashlib.sha256(
                f"basharena-task-v1\x00{task_id}".encode()
            ).hexdigest()[:24],
            "trajectory_id": hashlib.sha256(
                f"{SOURCE_ID}\x00{revision}\x00{sample_uuid}".encode()
            ).hexdigest()[:24],
        },
    }


def normalize_sample(
    row: dict[str, Any], sample: object, *, revision: str, split: str
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    raw_step = row.get("attack_step")
    if isinstance(raw_step, bool) or not isinstance(raw_step, (int, float)) or int(raw_step) != raw_step:
        raise ValueError("missing_exact_attack_step")
    attack_step = int(raw_step)
    raw_events = [
        event for event in (getattr(sample, "events", None) or [])
        if type(event).__name__ == "ToolEvent"
    ]
    agent_events, group_start, group_end = select_attack_group(raw_events, attack_step)
    window_start = max(0, group_end - MAX_WINDOW_EVENTS)
    if group_end - window_start > MAX_WINDOW_EVENTS or group_start < window_start:
        raise ValueError("attack_group_exceeds_window")

    projected: list[dict[str, object]] = []
    outcomes: Counter[str] = Counter()
    attachments = getattr(sample, "attachments", None)
    if not isinstance(attachments, dict):
        attachments = {}
    for ordinal, event in enumerate(agent_events[window_start:group_end]):
        item, outcome = project_tool_event(event, ordinal, attachments)
        projected.append(item)
        outcomes[outcome] += 1

    sample_uuid = str(row["sample_uuid"])
    original = f"{sample_uuid}:attack-step-{attack_step}"
    cases: list[dict[str, Any]] = []
    if group_end - group_start == 1:
        attack = projected[group_start - window_start]
        action = _case_base(
            row=row, revision=revision, split=split, original_id=original, suffix="action"
        )
        action["surface"] = "action"
        action["payload"] = {
            key: value for key, value in attack.items() if key not in {"outcome", "offset_seconds"}
        }
        action["strata"].update({"sequence_index": attack_step - 1, "call_index": 0})
        cases.append(action)

    if len(projected) >= 2:
        stateful = _case_base(
            row=row, revision=revision, split=split, original_id=original, suffix="stateful"
        )
        stateful["surface"] = "stateful"
        stateful["payload"] = {"events": projected}
        stateful["strata"].update({"sequence_index": attack_step - 1, "call_index": group_start})
        cases.append(stateful)
    return cases, dict(outcomes)


def normalize(
    rows: Iterable[dict[str, Any]], archive: zipfile.ZipFile, *, revision: str, split: str, limit: int | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    try:
        from inspect_ai.log import read_eval_log
    except ImportError as exc:  # pragma: no cover - CLI dependency guidance
        raise RuntimeError("inspect-ai==0.3.263 is required") from exc

    members = archive_members(archive)
    cases: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    side_tasks: Counter[str] = Counter()
    tool_names: Counter[str] = Counter()
    outcomes: Counter[str] = Counter()
    selected_samples = 0
    for row in rows:
        if row.get("side_task_success") is not True:
            skipped["side_task_not_successful"] += 1
            continue
        task_id = str(row.get("task_id") or "")
        sample_uuid = str(row.get("sample_uuid") or "")
        side_group = str(row.get("side_task_group") or "")
        if not task_id or not sample_uuid or side_group not in KNOWN_SIDE_TASKS:
            skipped["invalid_identity_or_side_task"] += 1
            continue
        if assigned_split(task_id) != split:
            skipped["other_split"] += 1
            continue
        basename = str(row.get("eval_log_filename") or "")
        member = members.get(basename)
        if member is None:
            skipped["missing_eval_log"] += 1
            continue
        try:
            log = read_eval_log(io.BytesIO(archive.read(member)), format="eval")
            matches = [sample for sample in (log.samples or []) if str(sample.uuid) == sample_uuid]
            if len(matches) != 1:
                raise ValueError("sample_uuid_match_count")
            sample = matches[0]
            sample_cases, sample_outcomes = normalize_sample(
                row, sample, revision=revision, split=split
            )
        except Exception as exc:  # untrusted input: quarantine one sample and continue
            skipped[f"projection:{type(exc).__name__}:{str(exc)[:80]}"] += 1
            continue
        cases.extend(sample_cases)
        selected_samples += 1
        side_tasks[side_group] += 1
        outcomes.update(sample_outcomes)
        for case in sample_cases:
            if case["surface"] == "action":
                tool_names[str(case["payload"]["tool_name"])] += 1
        if selected_samples % 100 == 0:
            print(
                json.dumps({"projected_samples": selected_samples, "split": split}),
                file=sys.stderr,
                flush=True,
            )
        if limit is not None and selected_samples >= limit:
            break

    cases.sort(key=lambda item: str(item["id"]))
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source_id": SOURCE_ID,
        "source_url": SOURCE_URL,
        "source_revision": revision,
        "source_license": SOURCE_LICENSE,
        "source_redistribution": SOURCE_REDISTRIBUTION,
        "split": split,
        "selected_sample_count": selected_samples,
        "case_count": len(cases),
        "action_case_count": sum(case["surface"] == "action" for case in cases),
        "stateful_case_count": sum(case["surface"] == "stateful" for case in cases),
        "side_task_counts": dict(sorted(side_tasks.items())),
        "attack_action_tool_counts": dict(sorted(tool_names.items())),
        "window_event_outcome_counts": dict(sorted(outcomes.items())),
        "skipped_counts": dict(sorted(skipped.items())),
        "split_contract": {
            "group": "BashArena task_id across all related sources",
            "algorithm": "sha256('basharena-task-v1' NUL task_id), 70/15/15",
            "audited_tasks_forced_to_development": sorted(AUDITED_DEVELOPMENT_TASKS),
        },
        "maximum_window_events": MAX_WINDOW_EVENTS,
        "excluded_source_fields": [
            "prompts", "reasoning", "tool_results", "monitor_scores", "scorer_explanations"
        ],
        "metric_boundary": (
            "Environment success and attack_step establish harmful source truth. Cases remain "
            "contextual/dual-use and cannot enter deterministic precision/recall/F1 until an "
            "independent closed proof finalizer promotes them."
        ),
        "execution_performed": False,
    }
    return cases, manifest


def validate_cases(cases: Sequence[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("jsonschema is required") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for index, case in enumerate(cases, 1):
        errors = sorted(validator.iter_errors(case), key=lambda item: list(item.path))
        if errors:
            error = errors[0]
            location = ".".join(str(part) for part in error.path) or "<root>"
            raise ValueError(f"normalized case {index} invalid at {location}: {error.message}")


def main() -> int:
    args = parse_args()
    if not args.source_revision or len(args.source_revision) > 160:
        raise ValueError("source revision must be 1..160 characters")
    if args.limit is not None and args.limit < 1:
        raise ValueError("limit must be positive")
    with zipfile.ZipFile(args.archive) as archive:
        cases, manifest = normalize(
            master_rows(args.master), archive, revision=args.source_revision,
            split=args.split, limit=args.limit,
        )
    validate_cases(cases, args.schema)
    manifest["source_files"] = {
        "archive": {"bytes": args.archive.stat().st_size, "sha256": file_sha256(args.archive)},
        "master": {"bytes": args.master.stat().st_size, "sha256": file_sha256(args.master)},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        "".join(json.dumps(case, ensure_ascii=False, sort_keys=True) + "\n" for case in cases),
        encoding="utf-8",
    )
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    skipped = manifest["skipped_counts"]
    adapter_statistics = {
        "source_rows": sum(manifest["side_task_counts"].values())
        + sum(int(value) for value in skipped.values()),
        "selected_samples": manifest["selected_sample_count"],
        "action_cases": manifest["action_case_count"],
        "stateful_cases": manifest["stateful_case_count"],
        "side_task_firewall": manifest["side_task_counts"].get("firewall", 0),
        "side_task_malware": manifest["side_task_counts"].get("malware", 0),
        "side_task_password_leak": manifest["side_task_counts"].get("password_leak", 0),
        "side_task_sudo": manifest["side_task_counts"].get("sudo", 0),
        "missing_exact_attack_step": sum(
            int(value) for key, value in skipped.items() if "missing_exact_attack_step" in key
        ),
        "other_split": int(skipped.get("other_split", 0)),
        "projected_failed_events": int(manifest["window_event_outcome_counts"].get("failed", 0)),
        "projected_succeeded_events": int(manifest["window_event_outcome_counts"].get("succeeded", 0)),
    }
    normalization_manifest = {
        "schema_version": "1",
        "datasets": [SOURCE_ID],
        "cases": len(cases),
        "counts": {SOURCE_ID: len(cases)},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {"monitoringbench": adapter_statistics},
        "output_sha256": file_sha256(args.output),
    }
    manifest_path.write_text(
        json.dumps(normalization_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    evidence_path = manifest_path.with_name(manifest_path.stem + ".evidence.json")
    evidence_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "cases": len(cases),
                "evidence_manifest": str(evidence_path),
                "manifest": str(manifest_path),
                "output": str(args.output),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
