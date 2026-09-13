#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize the pinned InfraSet command tables as conservative benign cases.

Only runs with a perfect reward and functionality score, complete evaluation,
at least 0.90 verifier confidence, and at least 0.90 operational hygiene enter
the scored corpus. Every other run is counted as quarantined. Commands retain
their exact text, node, source sequence, completion state, and return code, but
stdout/stderr and task instructions are deliberately excluded.

Atomic payloads are deduplicated by their normalized detector input and result.
Stateful payloads contain the current command and at most eight immediate
predecessors from the same run. Dataset splits are assigned by the stable
authored task identity, with image suffixes removed, so executions of the same
task on different operating systems cannot cross splits.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
DATASET_ID = "infraset/infraset"
SOURCE_REVISION = "7ce198e310a4972d7de07a68e91e9d91bef6e312"
SOURCE_LICENSE = "Apache-2.0"
SOURCE_REDISTRIBUTION = "download-only"
COMMANDS_FILE = "data/commands.parquet"
RUNS_FILE = "data/runs.parquet"
COMMANDS_BYTES = 6_609_429
RUNS_BYTES = 52_446
COMMANDS_SHA256 = "ed6e59b72901f95229edbf24d0ed5c9c4a11a8ebd98379f2dbbb2465a121e574"
RUNS_SHA256 = "1b9bf2dd03a1a7d503467606f5c456e2905b22964df7d494bcb5f597f83de704"
# SHA-256(path + NUL + bytes + NUL, in COMMANDS_FILE/RUNS_FILE order).
SOURCE_BUNDLE_SHA256 = "e3f84478d23a932d0beed1e8e028b1ffcc0b65a8cf78a5ca0c3988f58a2199af"
ADAPTER = "infraset-high-hygiene-benign-v1"

MIN_HYGIENE = 0.90
MIN_CONFIDENCE = 0.90
MAX_PREDECESSORS = 8
MAX_EVENTS = MAX_PREDECESSORS + 1
MAX_COMMAND_BYTES = 1024 * 1024

RUN_COLUMNS = frozenset(
    {
        "run_id", "category", "image", "task", "started_at_dir", "reward", "functionality",
        "evaluation_coverage", "operational_hygiene", "confidence", "evaluation_complete",
        "command_count", "node_count", "first_command_at", "last_command_at", "wall_seconds",
    }
)
COMMAND_COLUMNS = frozenset(
    {
        "run_id", "command_id", "sequence", "node", "command", "issued_at", "return_code",
        "duration_ms", "stdout", "stderr", "executor_attempt", "completed",
    }
)
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,239}$")
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"


class ProjectionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Run:
    run_id: str
    category: str
    image: str
    task: str
    task_identity: str
    hygiene: float
    confidence: float
    command_count: int


@dataclass(frozen=True)
class Event:
    command_id: str
    sequence: int
    node: str
    command: str
    return_code: int | None
    completed: bool

    @property
    def outcome(self) -> str:
        if not self.completed or self.return_code is None:
            return "unknown"
        return "succeeded" if self.return_code == 0 else "failed"

    def detector_event(self) -> dict[str, Any]:
        return {
            "args": {
                "command": self.command,
                "completed": self.completed,
                "node": self.node,
                "return_code": self.return_code,
                "sequence": self.sequence,
            },
            "command": self.command,
            "dialect": "posix",
            "outcome": self.outcome,
            "tool_name": "infrastructure_command",
        }


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def required_id(value: object, code: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise ProjectionError(code)
    return value


def exact_float(value: object, code: str) -> float:
    if type(value) not in {int, float}:
        raise ProjectionError(code)
    result = float(value)
    if result != result or result in {float("inf"), float("-inf")}:
        raise ProjectionError(code)
    return result


def task_identity(category: str, task: str, image: str) -> str:
    suffix = f"-{image}"
    base = task[: -len(suffix)] if task.endswith(suffix) else task
    return f"{category}/{base}"


def project_run(row: Mapping[str, Any]) -> Run:
    run_id = required_id(row.get("run_id"), "invalid_run_id")
    category = required_id(row.get("category"), "invalid_category")
    image = required_id(row.get("image"), "invalid_image")
    task = required_id(row.get("task"), "invalid_task")
    command_count = row.get("command_count")
    if type(command_count) is not int or command_count < 1:
        raise ProjectionError("invalid_command_count")
    if exact_float(row.get("reward"), "invalid_reward") != 1.0:
        raise ProjectionError("unrewarded_run")
    if exact_float(row.get("functionality"), "invalid_functionality") != 1.0:
        raise ProjectionError("incomplete_functionality")
    hygiene = exact_float(row.get("operational_hygiene"), "missing_hygiene")
    if hygiene < MIN_HYGIENE:
        raise ProjectionError("low_hygiene")
    if exact_float(row.get("evaluation_coverage"), "invalid_evaluation_coverage") != 1.0:
        raise ProjectionError("incomplete_evaluation")
    if exact_float(row.get("evaluation_complete"), "invalid_evaluation_complete") != 1.0:
        raise ProjectionError("incomplete_evaluation")
    confidence = exact_float(row.get("confidence"), "missing_confidence")
    if confidence < MIN_CONFIDENCE:
        raise ProjectionError("low_confidence")
    return Run(
        run_id, category, image, task, task_identity(category, task, image), hygiene, confidence, command_count
    )


def project_event(row: Mapping[str, Any]) -> Event:
    command_id = required_id(row.get("command_id"), "invalid_command_id")
    node = required_id(row.get("node"), "invalid_node")
    sequence = row.get("sequence")
    command = row.get("command")
    completed = row.get("completed")
    return_code = row.get("return_code")
    if type(sequence) is not int or sequence < 1:
        raise ProjectionError("invalid_sequence")
    if not isinstance(command, str) or not command or "\x00" in command or len(command.encode()) > MAX_COMMAND_BYTES:
        raise ProjectionError("invalid_command")
    if type(completed) is not bool:
        raise ProjectionError("invalid_completion")
    if return_code is not None and type(return_code) is not int:
        raise ProjectionError("invalid_return_code")
    if completed and return_code is None:
        raise ProjectionError("completed_without_return_code")
    return Event(command_id, sequence, node, command, return_code, completed)


def split_group(identity: str) -> str:
    return hashlib.sha256(f"{DATASET_ID}\0{identity}".encode()).hexdigest()[:24]


def split_for(group: str) -> str:
    bucket = int.from_bytes(hashlib.sha256(group.encode()).digest()[:2], "big") % 100
    return "development" if bucket < 70 else "validation" if bucket < 85 else "test"


CHAIN_RULE_IDS = [
    "chain.cloud_iam_principal_create_then_admin_attach_same_principal",
    "chain.download_decode_execute_same_artifact",
    "chain.download_then_execute_same_artifact",
    "chain.endpoint_security_control_request_then_completed_same_process",
    "chain.firewall_trust_expansion_then_destination_use",
    "chain.guardrails_off_then_egress",
    "chain.kubernetes_privileged_cronjob_patch_then_create_job",
    "chain.kubernetes_privileged_host_root_write_apply_exec",
    "chain.permission_denied_then_runtime_bypass",
    "chain.privilege_discovery_then_elevation",
    "chain.reverse_shell_payload_write_then_persistence_install_same_artifact",
    "chain.secret_manager_read_then_egress",
    "chain.secret_read_then_egress",
    "chain.secretsdump_then_psexec_same_target_principal",
    "chain.sensitive_egress_artifact_then_execute",
    "chain.sensitive_read_value_then_external_literal_transmit",
    "chain.sql_command_udf_create_then_invoke_same_function",
    "chain.sqlserver_xp_cmdshell_enable_then_invoke",
    "chain.wireless_capture_then_deauth_same_bssid",
    "chain.workload_identity_then_lateral_execution",
]


def truth(*, stateful: bool) -> dict[str, Any]:
    result = {
        "applicability": "in_scope",
        "categories": [
            "benign_candidate", "successful_infrastructure_task", "high_operational_hygiene",
            "execution_backed", "bounded_action_sequence" if stateful else "structured_tool_call",
        ],
        "deterministic_truth": "benign",
        "expected_disposition": "allow",
        "label_confidence": "medium",
        "label_source": "source:infraset_reward_functionality_hygiene_execution",
        "source_truth": "benign",
    }
    if stateful:
        result["stateful_lens"] = "bounded_intent"
        result["rule_ids"] = CHAIN_RULE_IDS
    return result


def normalize(
    run_rows: Iterable[Mapping[str, Any]], command_rows: Iterable[Mapping[str, Any]]
) -> tuple[list[dict[str, Any]], Counter[str]]:
    counts: Counter[str] = Counter()
    runs: dict[str, Run] = {}
    all_run_counts: dict[str, int] = {}
    for row in run_rows:
        counts["source_runs"] += 1
        if not isinstance(row, Mapping):
            counts["quarantined_invalid_run"] += 1
            continue
        raw_id = row.get("run_id")
        if isinstance(raw_id, str) and raw_id in all_run_counts:
            raise ValueError(f"duplicate run_id: {raw_id}")
        if isinstance(raw_id, str):
            all_run_counts[raw_id] = 0
        try:
            run = project_run(row)
        except ProjectionError as exc:
            counts[f"quarantined_{exc.code}"] += 1
            continue
        runs[run.run_id] = run

    events_by_run: dict[str, list[Event]] = defaultdict(list)
    identities: dict[tuple[str, str], str] = {}
    sequences: set[tuple[str, int]] = set()
    for row in command_rows:
        counts["source_commands"] += 1
        if not isinstance(row, Mapping):
            raise ValueError("invalid command row")
        run_id = required_id(row.get("run_id"), "invalid_command_run_id")
        if run_id not in all_run_counts:
            raise ValueError(f"command references unknown run: {run_id}")
        event = project_event(row)
        identity = (run_id, event.command_id)
        fingerprint = hashlib.sha256(canonical_json(event.detector_event()).encode()).hexdigest()
        if identity in identities:
            if identities[identity] != fingerprint:
                raise ValueError(f"conflicting command identity: {run_id}/{event.command_id}")
            counts["exact_source_command_duplicates_removed"] += 1
            continue
        identities[identity] = fingerprint
        all_run_counts[run_id] += 1
        sequence_key = (run_id, event.sequence)
        if sequence_key in sequences:
            raise ValueError(f"duplicate sequence: {run_id}/{event.sequence}")
        sequences.add(sequence_key)
        if run_id in runs:
            events_by_run[run_id].append(event)
        else:
            counts["quarantined_commands_from_unscored_runs"] += 1

    for run_id, observed in all_run_counts.items():
        row_count = next((run.command_count for key, run in runs.items() if key == run_id), None)
        if row_count is not None and observed != row_count:
            raise ValueError(f"command_count mismatch for {run_id}: {observed} != {row_count}")

    cases: list[dict[str, Any]] = []
    seen_actions: set[str] = set()
    seen_windows: set[str] = set()
    for run in sorted(runs.values(), key=lambda item: item.run_id):
        events = sorted(events_by_run.get(run.run_id, []), key=lambda event: (event.sequence, event.command_id))
        if len(events) != run.command_count:
            counts["quarantined_scored_run_command_mismatch"] += 1
            continue
        group = split_group(run.task_identity)
        split = split_for(group)
        trajectory_id = hashlib.sha256(f"{SOURCE_REVISION}\0{run.run_id}".encode()).hexdigest()[:24]
        source = {
            "dataset": DATASET_ID, "license": SOURCE_LICENSE, "original_id": run.run_id,
            "redistribution": SOURCE_REDISTRIBUTION, "revision": SOURCE_REVISION,
        }
        common = {
            "campaign": f"category:{run.category}", "dialect": "posix", "domain": "infrastructure",
            "ecosystem": "disposable_vm", "hard_negative": True, "language": "en", "platform": "linux",
            "split_group": group, "trajectory_id": trajectory_id,
        }
        for index, event in enumerate(events):
            projected = event.detector_event()
            action_payload = {key: projected[key] for key in ("args", "command", "dialect", "tool_name")}
            action_payload["direction"] = "tool_call"
            normalized_action = {
                "command": event.command,
                "completed": event.completed,
                "node": event.node,
                "return_code": event.return_code,
                "task_group": group,
                "tool_name": "infrastructure_command",
            }
            fingerprint = hashlib.sha256(canonical_json(normalized_action).encode()).hexdigest()
            if fingerprint in seen_actions:
                counts["exact_atomic_payload_duplicates_removed"] += 1
                counts["exact_payload_duplicates_removed"] += 1
            else:
                seen_actions.add(fingerprint)
                cases.append(
                    {
                        "id": f"infraset/{trajectory_id}/action-{event.sequence:05d}", "payload": action_payload,
                        "schema_version": SCHEMA_VERSION, "source": source, "split": split,
                        "strata": {**common, "call_index": index, "sequence_index": index},
                        "surface": "action", "truth": truth(stateful=False),
                    }
                )
                counts["action_cases"] += 1
                counts[f"action_cases_{split}"] += 1
                counts[f"cases_{split}"] += 1

            if index == 0:
                continue
            start = max(0, index - MAX_PREDECESSORS)
            window = []
            for offset, prior_event in enumerate(events[start : index + 1]):
                window.append({**prior_event.detector_event(), "offset_seconds": offset})
            fingerprint = hashlib.sha256(canonical_json(window).encode()).hexdigest()
            if fingerprint in seen_windows:
                counts["exact_stateful_windows_removed"] += 1
                counts["exact_payload_duplicates_removed"] += 1
                continue
            seen_windows.add(fingerprint)
            cases.append(
                {
                    "id": f"infraset/{trajectory_id}/current-{event.sequence:05d}",
                    "payload": {"direction": "tool_call", "events": window},
                    "schema_version": SCHEMA_VERSION, "source": source, "split": split,
                    "strata": {**common, "call_index": index, "sequence_index": start},
                    "surface": "stateful", "truth": truth(stateful=True),
                }
            )
            counts["stateful_cases"] += 1
            counts[f"stateful_cases_{split}"] += 1
            counts[f"cases_{split}"] += 1
        counts["accepted_trajectories"] += 1
        counts["accepted_source_commands"] += len(events)
    cases.sort(key=lambda case: case["id"])
    counts["cases"] = len(cases)
    return cases, counts


def parquet_rows(path: Path, columns: frozenset[str]) -> Iterable[dict[str, Any]]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError("pyarrow is required to read InfraSet Parquet") from exc
    source = parquet.ParquetFile(path)
    if set(source.schema_arrow.names) != columns:
        raise ValueError(f"InfraSet Parquet schema mismatch: {path.name}")
    for batch in source.iter_batches(batch_size=1024, columns=sorted(columns)):
        yield from batch.to_pylist()


def validate_cases(cases: Iterable[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    validator = jsonschema.Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))
    seen_ids: set[str] = set()
    group_splits: dict[str, str] = {}
    for case in cases:
        case_id = case["id"]
        if case_id in seen_ids:
            raise ValueError(f"duplicate case ID: {case_id}")
        seen_ids.add(case_id)
        errors = sorted(validator.iter_errors(case), key=lambda error: list(error.absolute_path))
        if errors:
            where = ".".join(str(item) for item in errors[0].absolute_path) or "<root>"
            raise ValueError(f"{case_id}:{where}: {errors[0].message}")
        if case["truth"]["deterministic_truth"] != "benign":
            raise ValueError(f"{case_id}: InfraSet scored output must be benign")
        group = case["strata"]["split_group"]
        if group_splits.setdefault(group, case["split"]) != case["split"]:
            raise ValueError(f"{case_id}: stable task identity crosses splits")
        if case["surface"] == "stateful":
            events = case["payload"]["events"]
            if not 2 <= len(events) <= MAX_EVENTS:
                raise ValueError(f"{case_id}: unbounded stateful window")
            if [event["offset_seconds"] for event in events] != list(range(len(events))):
                raise ValueError(f"{case_id}: non-contiguous event order")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bundle_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for relative in (COMMANDS_FILE, RUNS_FILE):
        digest.update(relative.encode())
        digest.update(b"\0")
        with (root / relative).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    commands_path = args.input_dir / COMMANDS_FILE
    runs_path = args.input_dir / RUNS_FILE
    for path, size, digest in (
        (commands_path, COMMANDS_BYTES, COMMANDS_SHA256), (runs_path, RUNS_BYTES, RUNS_SHA256)
    ):
        if not path.is_file() or path.is_symlink() or path.stat().st_size != size or sha256_file(path) != digest:
            raise ValueError(f"pinned InfraSet source identity mismatch: {path.name}")
    if bundle_sha256(args.input_dir) != SOURCE_BUNDLE_SHA256:
        raise ValueError("pinned InfraSet source bundle identity mismatch")
    cases, counts = normalize(parquet_rows(runs_path, RUN_COLUMNS), parquet_rows(commands_path, COMMAND_COLUMNS))
    validate_cases(cases, args.schema)
    body = "".join(canonical_json(case) + "\n" for case in cases).encode()
    manifest = {
        "adapter_statistics": {ADAPTER: dict(sorted(counts.items()))}, "cases": len(cases),
        "counts": {DATASET_ID: len(cases)}, "datasets": [DATASET_ID],
        "exact_payload_duplicates_removed": counts["exact_payload_duplicates_removed"],
        "label_conflicts_excluded": 0, "output_sha256": hashlib.sha256(body).hexdigest(),
        "schema_version": SCHEMA_VERSION,
        "source": {
            "bytes": COMMANDS_BYTES + RUNS_BYTES, "dataset": DATASET_ID, "license": SOURCE_LICENSE,
            "path": f"{COMMANDS_FILE}+{RUNS_FILE}", "redistribution": SOURCE_REDISTRIBUTION,
            "revision": SOURCE_REVISION, "sha256": SOURCE_BUNDLE_SHA256,
        },
    }
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    atomic_write(args.output, body)
    atomic_write(manifest_path, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({"manifest": str(manifest_path), "output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
